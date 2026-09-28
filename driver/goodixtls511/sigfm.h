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

#pragma once

#include <glib.h>

G_BEGIN_DECLS

typedef struct _SigfmInfo SigfmInfo;

/* Extracts SIFT features from an 8-bit grayscale image, upscaled by @scale */
SigfmInfo *sigfm_extract (const guint8 *pixels,
                          int           width,
                          int           height,
                          int           scale);

int        sigfm_keypoints_count (const SigfmInfo *info);

GBytes    *sigfm_serialize (const SigfmInfo *info);

SigfmInfo *sigfm_deserialize (GBytes *data);

/* Number of geometrically consistent match pairs; 0 means no match */
int        sigfm_match_score (const SigfmInfo *probe,
                              const SigfmInfo *enrolled);

void       sigfm_free (SigfmInfo *info);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (SigfmInfo, sigfm_free)

G_END_DECLS
