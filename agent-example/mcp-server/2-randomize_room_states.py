import random
import sqlite3

DB = "room.db"
ROOMS = [f"A-{i}" for i in range(1, 6)]

with sqlite3.connect(DB) as con:
    for room in ROOMS:
        light = random.choice([True, False])
        current_temp = random.choice([x / 2 for x in range(40, 61)])  # 20.0-30.0 C
        ac_temp = random.choice([x / 2 for x in range(40, 57)])       # 20.0-28.0 C

        con.execute(
            "UPDATE room_lights SET is_on = ? WHERE room_id = ?",
            (light, room),
        )
        con.execute(
            """
            UPDATE room_climate
            SET current_temperature = ?, ac_temperature = ?
            WHERE room_id = ?
            """,
            (current_temp, ac_temp, room),
        )

        print(
            f"{room}: light={'ON' if light else 'OFF'}, "
            f"room={current_temp:.1f} C, AC={ac_temp:.1f} C"
        )
