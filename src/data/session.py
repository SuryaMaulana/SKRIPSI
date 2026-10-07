"""Langkah 7 — fitur konteks dalam jendela waktu 60 detik, tanpa IP.

Semua baris SR-BH berasal dari satu alamat (gateway Docker), sehingga jendela dihitung atas seluruh lalu lintas
server (keputusan penulis). Untuk baris dengan detik t (resolusi stempel waktu = 1 detik), jendelanya adalah semua
permintaan dengan stempel waktu UTC dalam [t-59 dtk, t]. Itu berarti 60 detik penuh termasuk detik t, dan termasuk
permintaan lain pada detik yang sama karena urutan di dalam satu detik tidak diketahui.
Fitur dihitung atas seluruh aliran log yang terurai (termasuk baris yang nanti dikeluarkan atau duplikat),
karena itulah lalu lintas yang benar-benar diterima server.
"""

from __future__ import annotations

from collections import Counter, deque

import numpy as np
import pandas as pd

WINDOW_SECONDS = 60
FEATURES = ["sess_req_60s", "sess_4xx_ratio_60s", "sess_uniq_paths_60s"]


def session_features(timestamp: pd.Series, status: pd.Series, path: pd.Series, window: int = WINDOW_SECONDS) -> pd.DataFrame:
    """Jumlah permintaan, rasio status 4xx, dan jumlah path unik (path mentah) per jendela; NaN bila waktu tak ada."""
    valid = timestamp.notna()
    seconds = (timestamp[valid].astype("int64") // 10**9).to_numpy()
    is4xx = status[valid].between(400, 499).fillna(False).to_numpy()
    paths = path[valid].fillna("").tolist()

    order = np.argsort(seconds, kind="stable")
    uniq_sec, starts = np.unique(seconds[order], return_index=True)
    bounds = np.append(starts, len(order))

    req = np.zeros(len(uniq_sec), dtype=np.int64)
    bad = np.zeros(len(uniq_sec), dtype=np.int64)
    uniq = np.zeros(len(uniq_sec), dtype=np.int64)
    counter: Counter[str] = Counter()
    active: deque[int] = deque()
    n_req = n_bad = 0
    for i, sec in enumerate(uniq_sec):
        members = order[bounds[i]:bounds[i + 1]]
        for j in members:
            counter[paths[j]] += 1
        n_req += len(members)
        n_bad += int(is4xx[members].sum())
        active.append(i)
        while uniq_sec[active[0]] <= sec - window:
            old = active.popleft()
            gone = order[bounds[old]:bounds[old + 1]]
            for j in gone:
                counter[paths[j]] -= 1
                if not counter[paths[j]]:
                    del counter[paths[j]]
            n_req -= len(gone)
            n_bad -= int(is4xx[gone].sum())
        req[i], bad[i], uniq[i] = n_req, n_bad, len(counter)

    # petakan nilai per detik kembali ke setiap baris
    pos = np.searchsorted(uniq_sec, seconds)
    out = pd.DataFrame(np.nan, index=timestamp.index, columns=FEATURES)
    out.loc[valid, "sess_req_60s"] = req[pos]
    out.loc[valid, "sess_4xx_ratio_60s"] = bad[pos] / req[pos]
    out.loc[valid, "sess_uniq_paths_60s"] = uniq[pos]
    return out.astype({"sess_req_60s": "Int64", "sess_uniq_paths_60s": "Int64"})
