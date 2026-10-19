import sqlite3

DB = "room.db"

with sqlite3.connect(DB) as con:
    rows = con.execute(
        """
        SELECT l.room_id, l.is_on, c.current_temperature, c.ac_temperature
        FROM room_lights AS l
        JOIN room_climate AS c ON c.room_id = l.room_id
        ORDER BY l.room_id
        """
    )

    for room, light, current_temp, ac_temp in rows:
        print(
            f"{room}: light={'ON' if light else 'OFF'}, "
            f"room={current_temp:.1f} C, AC={ac_temp:.1f} C"
        )
