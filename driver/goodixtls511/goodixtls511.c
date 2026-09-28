/*
 * Goodix 27c6:5117 (TLS) driver for libfprint
 * Copyright (C) 2026 goodixtls511 contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * The sensor talks a Goodix "message pack" protocol over a CDC data
 * interface. Images are only sent through a TLS 1.2 PSK channel in which the
 * sensor is the client, so the driver runs a TLS server on memory BIOs.
 *
 * The sensor is too small (64x80) for NBIS minutiae matching, so the driver
 * matches on the host with SIGFM (SIFT features + geometric consistency) and
 * stores the features of each enrollment sample in the print.
 *
 * The sensor must first be provisioned with the known PSK and firmware (see
 * the provisioning tool shipped with the driver). Hardware finger detection
 * (FDT) does not work with the known parameters, so the driver polls frames
 * and detects the finger against a background frame.
 */

#define FP_COMPONENT "goodixtls511"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "drivers_api.h"
#include "goodixtls511.h"
#include "sigfm.h"

typedef enum {
  EXPECT_ACK,
  EXPECT_REPLY,
  EXPECT_REPLY_NO_CHECKSUM,
  EXPECT_TLS,
} GoodixExpect;

typedef enum {
  REPLY_NONE,               /* ACK only */
  REPLY_NO_ACK,             /* nothing (NOP) */
  REPLY_PROTOCOL,           /* ACK + protocol reply */
  REPLY_PROTOCOL_NO_CHECKSUM,
  REPLY_TLS,                /* ACK + raw TLS pack */
} GoodixReplyKind;

struct _FpiDeviceGoodixTls511
{
  FpDevice      parent;

  /* Transport */
  GByteArray   *rx;
  GByteArray   *reply;
  guint8        cmd;
  GoodixExpect  expect;
  int           jump_after_read;

  /* TLS */
  SSL_CTX      *ssl_ctx;
  SSL          *ssl;
  BIO          *rbio;
  BIO          *wbio;
  gboolean      tls_done;

  guint8        otp[64];

  /* Scanning */
  gboolean      activated;
  gboolean      finger_on;
  gboolean      need_finger_off;
  guint         settle;
  guint16      *background;
  guint8       *image;
  GPtrArray    *enroll_samples;
  guint         dump_count;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls511, fpi_device_goodixtls511, FPI,
                      DEVICE_GOODIXTLS511, FpDevice);
G_DEFINE_TYPE (FpiDeviceGoodixTls511, fpi_device_goodixtls511,
               FP_TYPE_DEVICE);

/* ---- Framing ------------------------------------------------------------ */

static void
write_pack (FpiSsm *ssm, FpDevice *dev, guint8 flags,
            const guint8 *payload, gsize len)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  gsize total = 4 + len;
  gsize padded = (total + GOODIX_USB_CHUNK - 1) / GOODIX_USB_CHUNK * GOODIX_USB_CHUNK;
  guint8 *buf = g_malloc0 (padded);

  buf[0] = flags;
  buf[1] = len & 0xff;
  buf[2] = len >> 8;
  buf[3] = (buf[0] + buf[1] + buf[2]) & 0xff;
  memcpy (buf + 4, payload, len);

  fpi_usb_transfer_fill_bulk_full (transfer, GOODIX_EP_OUT, buf, padded, g_free);
  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer, GOODIX_TIMEOUT, NULL,
                           fpi_ssm_usb_transfer_cb, NULL);
}

static void
write_command (FpiSsm *ssm, FpDevice *dev, guint8 cmd,
               const guint8 *payload, gsize len, gboolean checksum)
{
  g_autofree guint8 *msg = g_malloc (len + 4);
  guint8 sum = 0;

  msg[0] = cmd;
  msg[1] = (len + 1) & 0xff;
  msg[2] = (len + 1) >> 8;
  memcpy (msg + 3, payload, len);
  for (gsize i = 0; i < len + 3; i++)
    sum += msg[i];
  msg[len + 3] = checksum ? (guint8) (0xaa - sum) : 0x88;

  write_pack (ssm, dev, GOODIX_FLAGS_MSG, msg, len + 4);
}

static void read_pack (FpiSsm *ssm, FpDevice *dev);

/* Returns TRUE if the message was consumed, FALSE if it should be skipped. */
static gboolean
handle_pack (FpiDeviceGoodixTls511 *self, guint8 flags,
             const guint8 *data, gsize len, GError **error)
{
  guint8 cmd;
  gsize msg_len;
  guint8 sum = 0;

  if (flags == GOODIX_FLAGS_TLS)
    {
      if (self->expect != EXPECT_TLS)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Unexpected TLS message");
          return FALSE;
        }
      g_byte_array_set_size (self->reply, 0);
      g_byte_array_append (self->reply, data, len);
      return TRUE;
    }

  if (flags != GOODIX_FLAGS_MSG || len < 4)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid message pack (flags 0x%02x, length %zu)", flags, len);
      return FALSE;
    }

  cmd = data[0];
  msg_len = data[1] | data[2] << 8;
  if (msg_len < 1 || msg_len + 3 > len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid message length %zu", msg_len);
      return FALSE;
    }

  for (gsize i = 0; i < msg_len + 2; i++)
    sum += data[i];

  if (cmd == GOODIX_CMD_ACK)
    {
      if (msg_len < 3 || !(data[4] & 0x1))
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                       "Invalid ACK");
          return FALSE;
        }
      if (self->expect == EXPECT_ACK && data[3] == self->cmd)
        return TRUE;

      fp_dbg ("Skipping ACK for command 0x%02x", data[3]);
      return FALSE;
    }

  if (self->expect != EXPECT_REPLY && self->expect != EXPECT_REPLY_NO_CHECKSUM)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected reply to command 0x%02x", cmd);
      return FALSE;
    }

  if (cmd != self->cmd)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Reply to command 0x%02x while waiting for 0x%02x",
                   cmd, self->cmd);
      return FALSE;
    }

  if (self->expect == EXPECT_REPLY ?
      data[msg_len + 2] != (guint8) (0xaa - sum) : data[msg_len + 2] != 0x88)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid checksum in reply to 0x%02x", cmd);
      return FALSE;
    }

  g_byte_array_set_size (self->reply, 0);
  g_byte_array_append (self->reply, data + 3, msg_len - 1);
  return TRUE;
}

static void
read_pack_cb (FpiUsbTransfer *transfer, FpDevice *dev,
              gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  FpiSsm *ssm = transfer->ssm;
  GError *local_error = NULL;
  gsize pack_len;
  guint8 *buf;
  int jump;

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  g_byte_array_append (self->rx, transfer->buffer, transfer->actual_length);
  buf = self->rx->data;

  if (self->rx->len < 4)
    {
      read_pack (ssm, dev);
      return;
    }

  if (((buf[0] + buf[1] + buf[2]) & 0xff) != buf[3])
    {
      g_byte_array_set_size (self->rx, 0);
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Invalid pack header checksum"));
      return;
    }

  pack_len = buf[1] | buf[2] << 8;
  if (self->rx->len < pack_len + 4)
    {
      read_pack (ssm, dev);
      return;
    }

  /* Each transfer carries a single pack; anything after it is padding. */
  if (!handle_pack (self, buf[0], buf + 4, pack_len, &local_error))
    {
      g_byte_array_set_size (self->rx, 0);
      if (local_error)
        fpi_ssm_mark_failed (ssm, local_error);
      else
        read_pack (ssm, dev);
      return;
    }
  g_byte_array_set_size (self->rx, 0);

  jump = self->jump_after_read;
  self->jump_after_read = -1;
  if (jump >= 0)
    fpi_ssm_jump_to_state (ssm, jump);
  else
    fpi_ssm_next_state (ssm);
}

static void
read_pack (FpiSsm *ssm, FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_bulk (transfer, GOODIX_EP_IN, GOODIX_READ_SIZE);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, GOODIX_TIMEOUT, NULL, read_pack_cb, NULL);
}

static void
read_expect (FpiSsm *ssm, FpDevice *dev, GoodixExpect expect)
{
  FPI_DEVICE_GOODIXTLS511 (dev)->expect = expect;
  read_pack (ssm, dev);
}

/* ---- Commands ----------------------------------------------------------- */

typedef struct
{
  guint8          cmd;
  GoodixReplyKind kind;
  guint8         *payload;
  gsize           len;
} GoodixCommand;

static void
goodix_command_free (GoodixCommand *command)
{
  g_free (command->payload);
  g_free (command);
}

enum command_states {
  CMD_SEND,
  CMD_ACK,
  CMD_REPLY,
  CMD_NUM_STATES,
};

static void
command_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  GoodixCommand *command = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_SEND:
      self->cmd = command->cmd;
      write_command (ssm, dev, command->cmd, command->payload, command->len,
                     command->kind != REPLY_NO_ACK);
      break;

    case CMD_ACK:
      if (command->kind == REPLY_NO_ACK)
        fpi_ssm_mark_completed (ssm);
      else
        read_expect (ssm, dev, EXPECT_ACK);
      break;

    case CMD_REPLY:
      switch (command->kind)
        {
        case REPLY_PROTOCOL:
          read_expect (ssm, dev, EXPECT_REPLY);
          break;

        case REPLY_PROTOCOL_NO_CHECKSUM:
          read_expect (ssm, dev, EXPECT_REPLY_NO_CHECKSUM);
          break;

        case REPLY_TLS:
          read_expect (ssm, dev, EXPECT_TLS);
          break;

        case REPLY_NONE:
        case REPLY_NO_ACK:
          fpi_ssm_mark_completed (ssm);
          break;
        }
      break;
    }
}

/* Runs a command as a sub state machine of @parent; the reply payload is
 * left in self->reply. */
static void
goodix_command (FpiSsm *parent, FpDevice *dev, guint8 cmd,
                const guint8 *payload, gsize len, GoodixReplyKind kind)
{
  GoodixCommand *command = g_new0 (GoodixCommand, 1);
  FpiSsm *ssm = fpi_ssm_new (dev, command_run_state, CMD_NUM_STATES);

  command->cmd = cmd;
  command->kind = kind;
  command->payload = g_memdup2 (payload, len);
  command->len = len;
  fpi_ssm_set_data (ssm, command, (GDestroyNotify) goodix_command_free);
  fpi_ssm_silence_debug (ssm);
  fpi_ssm_start_subsm (parent, ssm);
}

static void
write_register (FpiSsm *ssm, FpDevice *dev, guint16 addr, guint16 value)
{
  const guint8 payload[] = { 0x00, addr & 0xff, addr >> 8, value & 0xff, value >> 8 };

  goodix_command (ssm, dev, GOODIX_CMD_WRITE_SENSOR_REGISTER,
                  payload, sizeof (payload), REPLY_NONE);
}

/* ---- TLS ---------------------------------------------------------------- */

static unsigned int
tls_psk_cb (SSL *ssl, const char *identity, unsigned char *psk,
            unsigned int max_psk_len)
{
  if (max_psk_len < sizeof (goodix_psk))
    return 0;

  memcpy (psk, goodix_psk, sizeof (goodix_psk));
  return sizeof (goodix_psk);
}

static GError *
tls_error (const char *what)
{
  unsigned long code = ERR_get_error ();
  char buf[256];

  ERR_error_string_n (code, buf, sizeof (buf));
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s: %s", what, buf);
}

static void
tls_free (FpiDeviceGoodixTls511 *self)
{
  /* The SSL object owns both BIOs */
  g_clear_pointer (&self->ssl, SSL_free);
  g_clear_pointer (&self->ssl_ctx, SSL_CTX_free);
  self->rbio = NULL;
  self->wbio = NULL;
  self->tls_done = FALSE;
}

static gboolean
tls_init (FpiDeviceGoodixTls511 *self, GError **error)
{
  tls_free (self);

  self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!self->ssl_ctx)
    goto fail;

  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  if (!SSL_CTX_set_cipher_list (self->ssl_ctx, "PSK-AES128-CBC-SHA256:@SECLEVEL=0"))
    goto fail;
  SSL_CTX_set_psk_server_callback (self->ssl_ctx, tls_psk_cb);

  self->ssl = SSL_new (self->ssl_ctx);
  self->rbio = BIO_new (BIO_s_mem ());
  self->wbio = BIO_new (BIO_s_mem ());
  if (!self->ssl || !self->rbio || !self->wbio)
    goto fail;

  SSL_set_bio (self->ssl, self->rbio, self->wbio);
  SSL_set_accept_state (self->ssl);
  return TRUE;

fail:
  *error = tls_error ("Failed to set up TLS server");
  tls_free (self);
  return FALSE;
}

/* Feeds self->reply to the handshake; returns FALSE on fatal errors. */
static gboolean
tls_handshake_step (FpiDeviceGoodixTls511 *self, GError **error)
{
  int ret;

  BIO_write (self->rbio, self->reply->data, self->reply->len);
  ret = SSL_do_handshake (self->ssl);
  if (ret == 1)
    {
      self->tls_done = TRUE;
      fp_dbg ("TLS established: %s", SSL_get_cipher_name (self->ssl));
      return TRUE;
    }

  if (SSL_get_error (self->ssl, ret) == SSL_ERROR_WANT_READ)
    return TRUE;

  *error = tls_error ("TLS handshake failed");
  return FALSE;
}

/* Sends whatever the TLS server wants to send; returns FALSE if nothing. */
static gboolean
tls_flush (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  size_t pending = BIO_ctrl_pending (self->wbio);
  g_autofree guint8 *buf = NULL;

  if (pending == 0)
    return FALSE;

  buf = g_malloc (pending);
  BIO_read (self->wbio, buf, pending);
  write_pack (ssm, dev, GOODIX_FLAGS_TLS, buf, pending);
  return TRUE;
}

static gboolean
tls_decrypt (FpiDeviceGoodixTls511 *self, GByteArray *out, GError **error)
{
  guint8 buf[4096];
  int ret;

  g_byte_array_set_size (out, 0);
  BIO_write (self->rbio, self->reply->data, self->reply->len);

  while ((ret = SSL_read (self->ssl, buf, sizeof (buf))) > 0)
    g_byte_array_append (out, buf, ret);

  if (SSL_get_error (self->ssl, ret) != SSL_ERROR_WANT_READ)
    {
      *error = tls_error ("TLS decryption failed");
      return FALSE;
    }

  return TRUE;
}

/* ---- Open --------------------------------------------------------------- */

enum open_states {
  OPEN_NOP,
  OPEN_ENABLE_CHIP,
  OPEN_NOP_2,
  OPEN_FIRMWARE,
  OPEN_CHECK_FIRMWARE,
  OPEN_PSK,
  OPEN_CHECK_PSK,
  OPEN_RESET,
  OPEN_CHECK_RESET,
  OPEN_OTP,
  OPEN_STORE_OTP,
  OPEN_RESET_2,
  OPEN_CHECK_RESET_2,
  OPEN_CONFIG,
  OPEN_CHECK_CONFIG,
  OPEN_POWERDOWN_FREQUENCY,
  OPEN_TLS_REQUEST,
  OPEN_TLS_FEED,
  OPEN_TLS_SEND,
  OPEN_TLS_LOOP,
  OPEN_TLS_ESTABLISHED,
  OPEN_NOP_3,
  OPEN_QUERY_MCU_STATE,
  OPEN_NUM_STATES,
};

static gboolean
check_reset (FpiDeviceGoodixTls511 *self, GError **error)
{
  const guint8 *r = self->reply->data;

  if (self->reply->len < 3 || r[0] != 0x01)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Sensor reset failed");
      return FALSE;
    }

  if ((r[1] | r[2] << 8) != GOODIX_RESET_NUMBER)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                         "Unexpected reset number %d", r[1] | r[2] << 8);
      return FALSE;
    }

  return TRUE;
}

static gboolean
check_firmware (FpiDeviceGoodixTls511 *self, GError **error)
{
  g_autofree gchar *version = g_strndup ((const gchar *) self->reply->data,
                                         self->reply->len);

  fp_info ("Firmware: %s", version);
  if (g_strcmp0 (version, GOODIX_FIRMWARE_VERSION) != 0)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                         "Unsupported firmware \"%s\" (expected \"%s\"); "
                                         "provision the sensor first",
                                         version, GOODIX_FIRMWARE_VERSION);
      return FALSE;
    }

  return TRUE;
}

static gboolean
check_psk (FpiDeviceGoodixTls511 *self, GError **error)
{
  const guint8 *r = self->reply->data;
  guint32 flags, len;

  if (self->reply->len < 9 || r[0] != 0x00)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Failed to read PSK");
      return FALSE;
    }

  flags = r[1] | r[2] << 8 | r[3] << 16 | (guint32) r[4] << 24;
  len = r[5] | r[6] << 8 | r[7] << 16 | (guint32) r[8] << 24;
  if (flags != GOODIX_PSK_FLAGS || len != sizeof (goodix_psk_hash) ||
      self->reply->len < 9 + len || memcmp (r + 9, goodix_psk_hash, len) != 0)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                         "Sensor uses an unknown PSK; provision the sensor first");
      return FALSE;
    }

  return TRUE;
}

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  GError *error = NULL;
  const guint8 zero[] = { 0x00, 0x00 };
  const guint8 nop[] = { 0x00, 0x00, 0x00, 0x00 };

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_NOP:
    case OPEN_NOP_2:
    case OPEN_NOP_3:
      goodix_command (ssm, dev, GOODIX_CMD_NOP, nop, sizeof (nop), REPLY_NO_ACK);
      break;

    case OPEN_ENABLE_CHIP:
      {
        const guint8 payload[] = { 0x01, 0x00 };
        goodix_command (ssm, dev, GOODIX_CMD_ENABLE_CHIP, payload,
                        sizeof (payload), REPLY_NONE);
      }
      break;

    case OPEN_FIRMWARE:
      goodix_command (ssm, dev, GOODIX_CMD_FIRMWARE_VERSION, zero,
                      sizeof (zero), REPLY_PROTOCOL);
      break;

    case OPEN_CHECK_FIRMWARE:
      if (check_firmware (self, &error))
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_mark_failed (ssm, error);
      break;

    case OPEN_PSK:
      {
        const guint8 payload[] = {
          GOODIX_PSK_FLAGS & 0xff, (GOODIX_PSK_FLAGS >> 8) & 0xff,
          (GOODIX_PSK_FLAGS >> 16) & 0xff, GOODIX_PSK_FLAGS >> 24,
          0x00, 0x00, 0x00, 0x00,
        };
        goodix_command (ssm, dev, GOODIX_CMD_PRESET_PSK_READ, payload,
                        sizeof (payload), REPLY_PROTOCOL);
      }
      break;

    case OPEN_CHECK_PSK:
      if (check_psk (self, &error))
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_mark_failed (ssm, error);
      break;

    case OPEN_RESET:
    case OPEN_RESET_2:
      {
        /* reset sensor, no MCU soft reset, 20 ms sleep */
        const guint8 payload[] = { 0x05, 20 };
        goodix_command (ssm, dev, GOODIX_CMD_RESET, payload, sizeof (payload),
                        REPLY_PROTOCOL);
      }
      break;

    case OPEN_CHECK_RESET:
    case OPEN_CHECK_RESET_2:
      if (check_reset (self, &error))
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_mark_failed (ssm, error);
      break;

    case OPEN_OTP:
      goodix_command (ssm, dev, GOODIX_CMD_READ_OTP, zero, sizeof (zero),
                      REPLY_PROTOCOL);
      break;

    case OPEN_STORE_OTP:
      if (self->reply->len < sizeof (self->otp))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Invalid OTP length %u",
                                                              self->reply->len));
          return;
        }
      memcpy (self->otp, self->reply->data, sizeof (self->otp));
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_CONFIG:
      goodix_command (ssm, dev, GOODIX_CMD_UPLOAD_CONFIG_MCU, goodix_mcu_config,
                      sizeof (goodix_mcu_config), REPLY_PROTOCOL);
      break;

    case OPEN_CHECK_CONFIG:
      if (self->reply->len < 1 || self->reply->data[0] != 0x01)
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Failed to upload MCU config"));
      else
        fpi_ssm_next_state (ssm);
      break;

    case OPEN_POWERDOWN_FREQUENCY:
      {
        const guint8 payload[] = { 100, 0x00 };
        goodix_command (ssm, dev, GOODIX_CMD_SET_POWERDOWN_SCAN_FREQUENCY,
                        payload, sizeof (payload), REPLY_PROTOCOL);
      }
      break;

    case OPEN_TLS_REQUEST:
      if (!tls_init (self, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      /* The reply is the sensor's ClientHello */
      goodix_command (ssm, dev, GOODIX_CMD_REQUEST_TLS_CONNECTION, zero,
                      sizeof (zero), REPLY_TLS);
      break;

    case OPEN_TLS_FEED:
      if (tls_handshake_step (self, &error))
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_mark_failed (ssm, error);
      break;

    case OPEN_TLS_SEND:
      if (!tls_flush (ssm, dev))
        fpi_ssm_next_state (ssm);
      break;

    case OPEN_TLS_LOOP:
      if (self->tls_done)
        {
          fpi_ssm_next_state_delayed (ssm, 10);
          return;
        }
      self->jump_after_read = OPEN_TLS_FEED;
      read_expect (ssm, dev, EXPECT_TLS);
      break;

    case OPEN_TLS_ESTABLISHED:
      goodix_command (ssm, dev, GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED, zero,
                      sizeof (zero), REPLY_NONE);
      break;

    case OPEN_QUERY_MCU_STATE:
      {
        const guint8 payload[] = { 0x55 };
        goodix_command (ssm, dev, GOODIX_CMD_QUERY_MCU_STATE, payload,
                        sizeof (payload), REPLY_PROTOCOL);
      }
      break;
    }
}

static void
open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);

      tls_free (self);
      g_clear_pointer (&self->rx, g_byte_array_unref);
      g_clear_pointer (&self->reply, g_byte_array_unref);
      g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                      GOODIX_INTERFACE,
                                      G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
                                      NULL);
    }

  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  GError *error = NULL;

  /* A previous session may have left the MCU mid-command; a USB reset makes
   * the first command reliable. */
  if (!g_usb_device_reset (usb_dev, &error))
    {
      fp_dbg ("USB reset failed: %s", error->message);
      g_clear_error (&error);
    }

  if (!g_usb_device_claim_interface (usb_dev, GOODIX_INTERFACE,
                                     G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
                                     &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  self->rx = g_byte_array_new ();
  self->reply = g_byte_array_new ();
  self->jump_after_read = -1;

  fpi_ssm_start (fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES), open_complete);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  GError *error = NULL;

  tls_free (self);
  g_clear_pointer (&self->rx, g_byte_array_unref);
  g_clear_pointer (&self->reply, g_byte_array_unref);
  g_clear_pointer (&self->background, g_free);
  g_clear_pointer (&self->image, g_free);
  g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);

  g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                  GOODIX_INTERFACE,
                                  G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
                                  &error);
  fpi_device_close_complete (dev, error);
}

/* ---- Activate ----------------------------------------------------------- */

enum activate_states {
  ACTIVATE_FDT_MODE,
  ACTIVATE_NAV,
  ACTIVATE_FDT_MODE_2,
  ACTIVATE_READ_REGISTER,
  ACTIVATE_WRITE_REGISTER_1,
  ACTIVATE_WRITE_REGISTER_2,
  ACTIVATE_WRITE_REGISTER_3,
  ACTIVATE_WRITE_REGISTER_4,
  ACTIVATE_NUM_STATES,
};

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_FDT_MODE:
      goodix_command (ssm, dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE,
                      goodix_fdt_mode_1, sizeof (goodix_fdt_mode_1), REPLY_PROTOCOL);
      break;

    case ACTIVATE_NAV:
      {
        const guint8 payload[] = { 0x01, 0x00 };
        goodix_command (ssm, dev, GOODIX_CMD_NAV, payload, sizeof (payload),
                        REPLY_PROTOCOL_NO_CHECKSUM);
      }
      break;

    case ACTIVATE_FDT_MODE_2:
      goodix_command (ssm, dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE,
                      goodix_fdt_mode_2, sizeof (goodix_fdt_mode_2), REPLY_PROTOCOL);
      break;

    case ACTIVATE_READ_REGISTER:
      {
        const guint8 payload[] = { 0x00, 0x82, 0x00, 0x02 };
        goodix_command (ssm, dev, GOODIX_CMD_READ_SENSOR_REGISTER, payload,
                        sizeof (payload), REPLY_PROTOCOL);
      }
      break;

    /* Per-sensor calibration values from the OTP */
    case ACTIVATE_WRITE_REGISTER_1:
      write_register (ssm, dev, 0x0220, self->otp[46] << 4 | 8);
      break;

    case ACTIVATE_WRITE_REGISTER_2:
      write_register (ssm, dev, 0x0236, self->otp[47]);
      break;

    case ACTIVATE_WRITE_REGISTER_3:
      write_register (ssm, dev, 0x0238, self->otp[48]);
      break;

    case ACTIVATE_WRITE_REGISTER_4:
      write_register (ssm, dev, 0x023a, self->otp[49]);
      break;
    }
}

/* ---- Scan --------------------------------------------------------------- */

enum scan_states {
  SCAN_ACTIVATE,
  SCAN_GET_IMAGE,
  SCAN_PROCESS,
  SCAN_WAIT,
  SCAN_NUM_STATES,
};

static gboolean
decode_frame (const GByteArray *plain, guint16 *frame, GError **error)
{
  const guint8 *p = plain->data + GOODIX_FRAME_HEADER;
  g_autofree guint16 *raw = NULL;

  if (plain->len != GOODIX_FRAME_SIZE)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                         "Unexpected frame size %u", plain->len);
      return FALSE;
    }

  raw = g_new (guint16, GOODIX_HEIGHT * GOODIX_STRIDE);
  for (gsize i = 0; i < GOODIX_HEIGHT * GOODIX_STRIDE; i += 4, p += 6)
    {
      raw[i] = ((p[0] & 0xf) << 8) | p[1];
      raw[i + 1] = (p[3] << 4) | (p[0] >> 4);
      raw[i + 2] = ((p[5] & 0xf) << 8) | p[2];
      raw[i + 3] = (p[4] << 4) | (p[5] >> 4);
    }

  for (gsize y = 0; y < GOODIX_HEIGHT; y++)
    memcpy (frame + y * GOODIX_WIDTH, raw + y * GOODIX_STRIDE,
            GOODIX_WIDTH * sizeof (guint16));

  return TRUE;
}

static int
compare_int (const void *a, const void *b)
{
  return *(const int *) a - *(const int *) b;
}

/* Finger pixels read lower than the background: build an 8-bit image of the
 * difference, stretched between the 2nd and 98th percentile. */
static guint8 *
build_image (const guint16 *background, const guint16 *frame)
{
  const gsize n = GOODIX_WIDTH * GOODIX_HEIGHT;
  guint8 *img = g_malloc (n);
  g_autofree int *diff = g_new (int, n);
  g_autofree int *sorted = NULL;
  int lo, hi;

  for (gsize i = 0; i < n; i++)
    diff[i] = (int) background[i] - (int) frame[i];

  sorted = g_memdup2 (diff, n * sizeof (int));
  qsort (sorted, n, sizeof (int), compare_int);
  lo = sorted[n * 2 / 100];
  hi = sorted[n * 98 / 100];
  if (hi <= lo)
    hi = lo + 1;

  for (gsize i = 0; i < n; i++)
    img[i] = CLAMP ((diff[i] - lo) * 255 / (hi - lo), 0, 255);

  return img;
}

static guint
frame_score (const guint16 *background, const guint16 *frame)
{
  const gsize n = GOODIX_WIDTH * GOODIX_HEIGHT;
  guint64 total = 0;

  for (gsize i = 0; i < n; i++)
    total += ABS ((int) background[i] - (int) frame[i]);

  return total / n;
}

static void
set_finger_on (FpiDeviceGoodixTls511 *self, gboolean on)
{
  self->finger_on = on;
  if (on)
    fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                             FP_FINGER_STATUS_PRESENT,
                                             FP_FINGER_STATUS_NONE);
  else
    fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                             FP_FINGER_STATUS_NONE,
                                             FP_FINGER_STATUS_PRESENT);
}

/* Debug aid: GOODIX511_DUMP_DIR=<dir> saves every captured image as PGM */
static void
dump_image (FpiDeviceGoodixTls511 *self)
{
  const gchar *dir = g_getenv ("GOODIX511_DUMP_DIR");
  g_autofree gchar *path = NULL;
  g_autofree gchar *header = NULL;
  g_autoptr(GByteArray) out = NULL;

  if (!dir)
    return;

  path = g_strdup_printf ("%s/goodix511-%03u.pgm", dir, self->dump_count++);
  header = g_strdup_printf ("P5 %d %d 255\n", GOODIX_WIDTH, GOODIX_HEIGHT);
  out = g_byte_array_new ();
  g_byte_array_append (out, (guint8 *) header, strlen (header));
  g_byte_array_append (out, self->image, GOODIX_WIDTH * GOODIX_HEIGHT);
  if (!g_file_set_contents (path, (gchar *) out->data, out->len, NULL))
    fp_warn ("Failed to write %s", path);
}

/* Returns TRUE once a finger image is available in self->image. */
static gboolean
process_frame (FpiDeviceGoodixTls511 *self, const guint16 *frame)
{
  const gsize n = GOODIX_WIDTH * GOODIX_HEIGHT;
  guint score;

  if (!self->background)
    {
      self->background = g_memdup2 (frame, n * sizeof (guint16));
      return FALSE;
    }

  score = frame_score (self->background, frame);

  if (!self->finger_on)
    {
      if (score > GOODIX_FINGER_ON_THRESHOLD && !self->need_finger_off)
        {
          fp_dbg ("Finger on (score %u)", score);
          set_finger_on (self, TRUE);
          self->settle = 1;
          return FALSE;
        }

      if (score < GOODIX_FINGER_OFF_THRESHOLD)
        {
          self->need_finger_off = FALSE;
          /* Track slow drift of the empty sensor */
          for (gsize i = 0; i < n; i++)
            self->background[i] = (self->background[i] * 7 + frame[i]) / 8;
        }
      return FALSE;
    }

  if (score < GOODIX_FINGER_OFF_THRESHOLD)
    {
      fp_dbg ("Finger off (score %u)", score);
      set_finger_on (self, FALSE);
      self->need_finger_off = FALSE;
      return FALSE;
    }

  /* Let the finger settle for a frame before capturing */
  if (self->settle > 0)
    {
      self->settle--;
      return FALSE;
    }

  if (self->need_finger_off)
    return FALSE;

  fp_dbg ("Capturing image (score %u)", score);
  g_clear_pointer (&self->image, g_free);
  self->image = build_image (self->background, frame);
  self->need_finger_off = TRUE;
  dump_image (self);
  return TRUE;
}

static void
scan_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  g_autoptr(GByteArray) plain = NULL;
  g_autofree guint16 *frame = NULL;
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_ACTIVATE:
      if (self->activated)
        {
          fpi_ssm_next_state (ssm);
          return;
        }
      self->activated = TRUE;
      fpi_ssm_start_subsm (ssm, fpi_ssm_new (dev, activate_run_state,
                                             ACTIVATE_NUM_STATES));
      break;

    case SCAN_GET_IMAGE:
      {
        const guint8 payload[] = { 0x01, 0x00 };
        goodix_command (ssm, dev, GOODIX_CMD_MCU_GET_IMAGE, payload,
                        sizeof (payload), REPLY_TLS);
      }
      break;

    case SCAN_PROCESS:
      plain = g_byte_array_new ();
      frame = g_new (guint16, GOODIX_WIDTH * GOODIX_HEIGHT);
      if (!tls_decrypt (self, plain, &error) || !decode_frame (plain, frame, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      if (process_frame (self, frame))
        fpi_ssm_mark_completed (ssm);
      else
        fpi_ssm_next_state (ssm);
      break;

    case SCAN_WAIT:
      if (g_cancellable_set_error_if_cancelled (fpi_device_get_cancellable (dev), &error))
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_jump_to_state_delayed (ssm, SCAN_GET_IMAGE, GOODIX_POLL_INTERVAL);
      break;
    }
}

/* Captures one finger image into self->image, then calls @callback. */
static void
start_scan (FpDevice *dev, FpiSsmCompletedCallback callback)
{
  FpiSsm *ssm = fpi_ssm_new (dev, scan_run_state, SCAN_NUM_STATES);

  fpi_ssm_silence_debug (ssm);
  fpi_ssm_start (ssm, callback);
}

static void
start_action (FpiDeviceGoodixTls511 *self)
{
  self->activated = FALSE;
  /* A finger still resting from the previous action must be lifted first */
  self->need_finger_off = self->finger_on;
  g_clear_pointer (&self->image, g_free);
  fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                           FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_NONE);
}

/* Fraction of 8x8 blocks showing ridges; low values mean partial contact */
static double
image_coverage (const guint8 *img)
{
  guint covered = 0, total = 0;

  for (guint by = 0; by < GOODIX_HEIGHT; by += 8)
    for (guint bx = 0; bx < GOODIX_WIDTH; bx += 8)
      {
        double sum = 0, sum_sq = 0;

        for (guint y = by; y < by + 8; y++)
          for (guint x = bx; x < bx + 8; x++)
            {
              double v = img[y * GOODIX_WIDTH + x];
              sum += v;
              sum_sq += v * v;
            }
        if (sum_sq / 64 - (sum / 64) * (sum / 64) >
            GOODIX_BLOCK_MIN_STDDEV * GOODIX_BLOCK_MIN_STDDEV)
          covered++;
        total++;
      }

  return (double) covered / total;
}

/* Extracts features from self->image; on failure sets a retry error. */
static SigfmInfo *
extract_features (FpiDeviceGoodixTls511 *self, GError **error)
{
  double coverage = image_coverage (self->image);
  SigfmInfo *info;

  if (coverage < GOODIX_MIN_COVERAGE)
    {
      fp_dbg ("Partial contact (coverage %.2f)", coverage);
      *error = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
      return NULL;
    }

  info = sigfm_extract (self->image, GOODIX_WIDTH, GOODIX_HEIGHT,
                        GOODIX_SIGFM_SCALE);

  if (info && sigfm_keypoints_count (info) >= GOODIX_SIGFM_MIN_KEYPOINTS)
    return info;

  fp_dbg ("Too few keypoints (%d)", info ? sigfm_keypoints_count (info) : -1);
  g_clear_pointer (&info, sigfm_free);
  *error = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
  return NULL;
}

/* Best SIGFM score of @probe against every sample of @print */
static int
match_print (FpPrint *print, const SigfmInfo *probe)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) samples = NULL;
  GVariantIter iter;
  GVariant *sample;
  guint32 version;
  int best = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, "(u@aay)", FALSE))
    return 0;

  g_variant_get (data, "(u@aay)", &version, &samples);
  if (version != GOODIX_PRINT_VERSION)
    return 0;

  g_variant_iter_init (&iter, samples);
  while ((sample = g_variant_iter_next_value (&iter)))
    {
      g_autoptr(GBytes) bytes = g_variant_get_data_as_bytes (sample);
      g_autoptr(SigfmInfo) enrolled = sigfm_deserialize (bytes);

      if (enrolled)
        best = MAX (best, sigfm_match_score (probe, enrolled));
      g_variant_unref (sample);
    }

  fp_dbg ("Best match score %d (threshold %d)", best, GOODIX_SIGFM_THRESHOLD);
  return best;
}

/* ---- Enroll ------------------------------------------------------------- */

static void enroll_scan_done (FpiSsm *ssm, FpDevice *dev, GError *error);

static void
enroll_finish (FpiDeviceGoodixTls511 *self)
{
  FpDevice *dev = FP_DEVICE (self);
  GVariantBuilder builder;
  FpPrint *print;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));
  for (guint i = 0; i < self->enroll_samples->len; i++)
    {
      GBytes *bytes = g_ptr_array_index (self->enroll_samples, i);
      g_variant_builder_add_value (&builder,
                                   g_variant_new_from_bytes (G_VARIANT_TYPE_BYTESTRING,
                                                             bytes, TRUE));
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data",
                g_variant_new ("(u@aay)", GOODIX_PRINT_VERSION,
                               g_variant_builder_end (&builder)),
                NULL);

  g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
enroll_scan_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  g_autoptr(SigfmInfo) info = NULL;
  GError *retry = NULL;

  if (error)
    {
      g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  info = extract_features (self, &retry);
  if (!info)
    {
      fpi_device_enroll_progress (dev, self->enroll_samples->len, NULL, retry);
      start_scan (dev, enroll_scan_done);
      return;
    }

  g_ptr_array_add (self->enroll_samples, sigfm_serialize (info));
  fpi_device_enroll_progress (dev, self->enroll_samples->len, NULL, NULL);

  if (self->enroll_samples->len >= fp_device_get_nr_enroll_stages (dev))
    enroll_finish (self);
  else
    start_scan (dev, enroll_scan_done);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);

  start_action (self);
  g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);
  self->enroll_samples = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  start_scan (dev, enroll_scan_done);
}

/* ---- Verify / identify -------------------------------------------------- */

static void
verify_scan_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  g_autoptr(SigfmInfo) info = NULL;
  GError *retry = NULL;
  FpPrint *print;

  if (error)
    {
      fpi_device_verify_complete (dev, error);
      return;
    }

  info = extract_features (self, &retry);
  if (!info)
    {
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, retry);
      fpi_device_verify_complete (dev, NULL);
      return;
    }

  fpi_device_get_verify_data (dev, &print);
  fpi_device_verify_report (dev,
                            match_print (print, info) >= GOODIX_SIGFM_THRESHOLD ?
                            FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                            NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
dev_verify (FpDevice *dev)
{
  start_action (FPI_DEVICE_GOODIXTLS511 (dev));
  start_scan (dev, verify_scan_done);
}

static void
identify_scan_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls511 *self = FPI_DEVICE_GOODIXTLS511 (dev);
  g_autoptr(SigfmInfo) info = NULL;
  GError *retry = NULL;
  FpPrint *best_print = NULL;
  GPtrArray *prints;
  int best = 0;

  if (error)
    {
      fpi_device_identify_complete (dev, error);
      return;
    }

  info = extract_features (self, &retry);
  if (!info)
    {
      fpi_device_identify_report (dev, NULL, NULL, retry);
      fpi_device_identify_complete (dev, NULL);
      return;
    }

  fpi_device_get_identify_data (dev, &prints);
  for (guint i = 0; i < prints->len; i++)
    {
      FpPrint *print = g_ptr_array_index (prints, i);
      int score = match_print (print, info);

      if (score >= GOODIX_SIGFM_THRESHOLD && score > best)
        {
          best = score;
          best_print = print;
        }
    }

  fpi_device_identify_report (dev, best_print, NULL, NULL);
  fpi_device_identify_complete (dev, NULL);
}

static void
dev_identify (FpDevice *dev)
{
  start_action (FPI_DEVICE_GOODIXTLS511 (dev));
  start_scan (dev, identify_scan_done);
}

/* ---- Class -------------------------------------------------------------- */

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x5117, },
  { .vid = 0,      .pid = 0, },
};

static void
fpi_device_goodixtls511_init (FpiDeviceGoodixTls511 *self)
{
}

static void
fpi_device_goodixtls511_class_init (FpiDeviceGoodixTls511Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Goodix 5117 TLS Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = GOODIX_ENROLL_STAGES;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;

  fpi_device_class_auto_initialize_features (dev_class);
}
