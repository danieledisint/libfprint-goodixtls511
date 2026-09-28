/*
 * SIGFM: SIFT-based matcher for small fingerprint sensors
 * Copyright (C) 2022 Natasha England-Elbro, Alexander Meiler (original)
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
 * SIFT keypoints are matched with Lowe's ratio test; the score counts pairs
 * of matched keypoint pairs whose relative rotation agrees, which rejects
 * matches that are not consistent with a single rigid transform.
 */

#include "sigfm.h"

#include <cmath>
#include <cstring>
#include <set>
#include <tuple>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#if __has_include(<opencv2/features.hpp>)
#include <opencv2/features.hpp>
#else
#include <opencv2/features2d.hpp>
#endif

namespace {

constexpr double distance_match = 0.75;
constexpr double length_match = 0.05;
constexpr double angle_match = 0.05;
constexpr std::size_t min_match = 5;
constexpr guint32 format_magic = 0x31464753; /* "SGF1" */
constexpr int descriptor_size = 128;

using Point = std::pair<int, int>;
using Match = std::pair<Point, Point>;

struct Angle
{
  double cos;
  double sin;
};

bool
ratio_close (double a, double b, double tolerance)
{
  double hi = std::max (a, b);

  return hi > 0 && 1 - std::min (a, b) / hi <= tolerance;
}

} // namespace

struct _SigfmInfo
{
  std::vector<cv::KeyPoint> keypoints;
  cv::Mat                   descriptors;
};

SigfmInfo *
sigfm_extract (const guint8 *pixels, int width, int height, int scale)
{
  try
    {
      cv::Mat img (height, width, CV_8UC1, const_cast<guint8 *> (pixels));
      cv::Mat scaled;
      auto *info = new SigfmInfo;

      if (scale > 1)
        cv::resize (img, scaled, cv::Size (), scale, scale, cv::INTER_CUBIC);
      else
        scaled = img.clone ();

      cv::SIFT::create ()->detectAndCompute (scaled, cv::noArray (),
                                             info->keypoints, info->descriptors);
      return info;
    }
  catch (const cv::Exception &e)
    {
      g_warning ("SIFT extraction failed: %s", e.what ());
      return nullptr;
    }
}

int
sigfm_keypoints_count (const SigfmInfo *info)
{
  return info->keypoints.size ();
}

/* Layout (little endian): magic, count, then per keypoint x, y as float32,
 * then count * 128 descriptor bytes. OpenCV SIFT descriptors are integral
 * values in 0..255, so the byte encoding is lossless. */
GBytes *
sigfm_serialize (const SigfmInfo *info)
{
  guint32 count = info->keypoints.size ();
  GByteArray *out = g_byte_array_new ();
  guint32 header[2] = { GUINT32_TO_LE (format_magic), GUINT32_TO_LE (count) };

  g_byte_array_append (out, reinterpret_cast<guint8 *> (header), sizeof (header));

  for (const auto &kp : info->keypoints)
    {
      float xy[2] = { kp.pt.x, kp.pt.y };
      g_byte_array_append (out, reinterpret_cast<guint8 *> (xy), sizeof (xy));
    }

  for (guint32 i = 0; i < count; i++)
    {
      guint8 row[descriptor_size];
      for (int j = 0; j < descriptor_size; j++)
        row[j] = cv::saturate_cast<guint8> (info->descriptors.at<float> (i, j));
      g_byte_array_append (out, row, sizeof (row));
    }

  return g_byte_array_free_to_bytes (out);
}

SigfmInfo *
sigfm_deserialize (GBytes *data)
{
  gsize len;
  const guint8 *p = static_cast<const guint8 *> (g_bytes_get_data (data, &len));
  guint32 header[2];
  guint32 count;

  if (len < sizeof (header))
    return nullptr;

  memcpy (header, p, sizeof (header));
  count = GUINT32_FROM_LE (header[1]);
  if (GUINT32_FROM_LE (header[0]) != format_magic ||
      len != sizeof (header) + (gsize) count * (2 * sizeof (float) + descriptor_size))
    return nullptr;

  auto *info = new SigfmInfo;
  p += sizeof (header);
  info->keypoints.reserve (count);
  for (guint32 i = 0; i < count; i++, p += 2 * sizeof (float))
    {
      float xy[2];
      memcpy (xy, p, sizeof (xy));
      info->keypoints.emplace_back (xy[0], xy[1], 1.0f);
    }

  info->descriptors.create (count, descriptor_size, CV_32F);
  for (guint32 i = 0; i < count; i++)
    for (int j = 0; j < descriptor_size; j++)
      info->descriptors.at<float> (i, j) = *p++;

  return info;
}

int
sigfm_match_score (const SigfmInfo *probe, const SigfmInfo *enrolled)
{
  try
    {
      std::vector<std::vector<cv::DMatch>> knn;
      std::set<Match> unique;

      if (probe->keypoints.size () < 2 || enrolled->keypoints.size () < 2)
        return 0;

      cv::BFMatcher::create ()->knnMatch (probe->descriptors,
                                          enrolled->descriptors, knn, 2);
      for (const auto &pair : knn)
        {
          if (pair.size () < 2 || pair[0].distance >= distance_match * pair[1].distance)
            continue;

          const auto &p1 = probe->keypoints[pair[0].queryIdx].pt;
          const auto &p2 = enrolled->keypoints[pair[0].trainIdx].pt;
          unique.emplace (Point ((int) p1.x, (int) p1.y), Point ((int) p2.x, (int) p2.y));
        }

      if (unique.size () < min_match)
        return 0;

      std::vector<Match> matches (unique.begin (), unique.end ());
      std::vector<Angle> angles;
      for (std::size_t j = 0; j < matches.size (); j++)
        for (std::size_t k = j + 1; k < matches.size (); k++)
          {
            const auto &[a1, b1] = matches[j];
            const auto &[a2, b2] = matches[k];
            double v1x = a1.first - a2.first, v1y = a1.second - a2.second;
            double v2x = b1.first - b2.first, v2y = b1.second - b2.second;
            double l1 = std::hypot (v1x, v1y), l2 = std::hypot (v2x, v2y);

            if (l1 == 0 || l2 == 0 || !ratio_close (l1, l2, length_match))
              continue;

            double product = l1 * l2;
            double s = std::clamp ((v1x * v2x + v1y * v2y) / product, -1.0, 1.0);
            double c = std::clamp ((v1x * v2y - v1y * v2x) / product, -1.0, 1.0);
            angles.push_back ({ M_PI / 2 + std::asin (s), std::acos (c) });
          }

      if (angles.size () < min_match)
        return 0;

      int count = 0;
      for (std::size_t j = 0; j < angles.size (); j++)
        for (std::size_t k = j + 1; k < angles.size (); k++)
          if (ratio_close (angles[j].sin, angles[k].sin, angle_match) &&
              ratio_close (angles[j].cos, angles[k].cos, angle_match))
            count++;

      return count;
    }
  catch (const cv::Exception &e)
    {
      g_warning ("SIGFM matching failed: %s", e.what ());
      return 0;
    }
}

void
sigfm_free (SigfmInfo *info)
{
  delete info;
}
