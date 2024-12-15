from flask import Blueprint, jsonify, request
from utils.jwtToken import token_required
from db import get_db_connection
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta

trigger_bp = Blueprint("trigger", __name__)

scheduler = BackgroundScheduler()
def schedule_event(trigger):
    if 'schedule_time' in trigger and trigger['schedule_time']:
        trigger_time = datetime.fromisoformat(trigger['schedule_time'])
        scheduler.add_job(
            log_event,
            CronTrigger(hour=trigger_time.hour, minute=trigger_time.minute),
            args=[trigger]
        )
    elif 'interval' in trigger and trigger['interval']:
        scheduler.add_job(
            log_event,
            IntervalTrigger(minutes=trigger['interval']),
            args=[trigger]
        )


# Logs the event and reschedules if necessary
def log_event(trigger, is_test=False):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Insert log entry
            cursor.execute('''
                INSERT INTO event_logs (trigger_id, status, api_payload, is_test)
                VALUES (?, ?, ?, ?)
            ''', (trigger['trigger_id'], 'triggered', trigger['api_payload'], is_test))

            conn.commit()
        if trigger['is_recurring'] and not is_test:
            schedule_event(trigger)
    except Exception as e:
        print(f"Error logging event: {str(e)}")


@trigger_bp.route("/create-trigger", methods=["POST"])
@token_required
def create_trigger(username):
    data = request.json
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "User not found!"}), 404

            user_id = user['id']  

        trigger_type = data.get("trigger_type")
        schedule_time = data.get("schedule_time")
        interval = data.get("interval")
        api_endpoint = data.get("api_endpoint")
        api_payload = data.get("api_payload")
        is_recurring = data.get("is_recurring", False)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (user_id, trigger_type, schedule_time, interval, api_endpoint, api_payload, is_recurring)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, trigger_type, schedule_time, interval, api_endpoint, api_payload, is_recurring))
            conn.commit()

            trigger_id = cursor.lastrowid  
            cursor.execute('SELECT * FROM events WHERE trigger_id = ?', (trigger_id,))
            trigger = cursor.fetchone()

        if trigger:
            schedule_event(trigger)
            return jsonify({"message": "Trigger created successfully"}), 201
        return jsonify({"error": "Failed to create trigger"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@trigger_bp.route("/list-triggers", methods=["GET"])
@token_required
def list_triggers(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT * 
                FROM events 
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
            """
            cursor.execute(query, (username,))
            triggers = cursor.fetchall()

        result = [dict(trigger) for trigger in triggers]
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@trigger_bp.route('/trigger_event/<int:trigger_id>', methods=['POST'])
def trigger_event(trigger_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events WHERE trigger_id = ?', (trigger_id,))
            trigger = cursor.fetchone()

        if trigger:
            log_event(trigger)
            return jsonify({"message": "Event triggered successfully!"}), 200
        return jsonify({"error": "Trigger not found!"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@trigger_bp.route('/test_trigger/<int:trigger_id>', methods=['POST'])
def test_trigger(trigger_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events WHERE trigger_id = ?', (trigger_id,))
            trigger = cursor.fetchone()

        if trigger:
            log_event(trigger, is_test=True)
            return jsonify({"message": "Test event triggered successfully!"}), 200
        return jsonify({"error": "Trigger not found!"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@trigger_bp.route('/update-trigger/<int:trigger_id>', methods=['PUT'])
@token_required
def update_trigger(username, trigger_id):
    data = request.json
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events WHERE trigger_id = ?', (trigger_id,))
            trigger = cursor.fetchone()

            if not trigger:
                return jsonify({"error": "Trigger not found!"}), 404

            schedule_time = data.get("schedule_time", trigger['schedule_time'])
            interval = data.get("interval", trigger['interval'])
            api_endpoint = data.get("api_endpoint", trigger['api_endpoint'])
            api_payload = data.get("api_payload", trigger['api_payload'])
            is_recurring = data.get("is_recurring", trigger['is_recurring'])

            cursor.execute('''
                UPDATE events
                SET schedule_time = ?, interval = ?, api_endpoint = ?, api_payload = ?, is_recurring = ?
                WHERE trigger_id = ?
            ''', (schedule_time, interval, api_endpoint, api_payload, is_recurring, trigger_id))

            conn.commit()

            cursor.execute('SELECT * FROM events WHERE trigger_id = ?', (trigger_id,))
            updated_trigger = cursor.fetchone()

        if updated_trigger:
            schedule_event(updated_trigger)
            return jsonify({"message": "Trigger updated successfully!"}), 200
        return jsonify({"error": "Failed to update trigger"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@trigger_bp.route('/delete-trigger/<int:trigger_id>', methods=['DELETE'])
@token_required
def delete_trigger(username, trigger_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events WHERE trigger_id = ?', (trigger_id,))
            trigger = cursor.fetchone()

            if not trigger:
                return jsonify({"error": "Trigger not found!"}), 404

            cursor.execute('DELETE FROM events WHERE trigger_id = ?', (trigger_id,))
            conn.commit()

            return jsonify({"message": "Trigger deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def clean_event_logs():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE event_logs 
                SET status = "archived" 
                WHERE triggered_at < ?
            ''', (datetime.now() - timedelta(hours=2),))

            cursor.execute('''
                DELETE FROM event_logs 
                WHERE triggered_at < ?
            ''', (datetime.now() - timedelta(hours=48),))

            conn.commit()

    except Exception as e:
        print(f"Error cleaning event logs: {str(e)}")


scheduler.add_job(clean_event_logs, IntervalTrigger(hours=2))
