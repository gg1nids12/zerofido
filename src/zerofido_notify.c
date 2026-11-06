/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "zerofido_notify.h"

#include <notification/notification_messages.h>

#include "zerofido_app_i.h"
#include "zerofido_ui_i.h"

#define ZF_NOTIFY_WINK_MS 250
#define ZF_NOTIFY_SUCCESS_MS 350
#define ZF_NOTIFY_ERROR_MS 500

/*
 * tpm branch (2026-11-05): when OK is needed the owner wants a few seconds of
 * vibration and a clear light. A timer drives both, so pressing OK (or deny,
 * timeout, cancel) stops them at once: 4 vibration pulses over ~3 s, and the
 * LED blinks blue until the request is answered. The Flipper vibration setting
 * is respected.
 */
#define ZF_PROMPT_TICK_MS 375U
#define ZF_PROMPT_VIBRO_PULSES 4U

static FuriTimer *zf_prompt_timer;
static NotificationApp *zf_prompt_notifications;
static uint32_t zf_prompt_tick;

static const NotificationSequence zf_sequence_prompt_pulse = {
    &message_vibro_on, &message_delay_250, &message_vibro_off, NULL,
};

static const NotificationSequence zf_sequence_prompt_led_on = {
    &message_red_0, &message_green_0, &message_blue_255, &message_do_not_reset, NULL,
};

static const NotificationSequence zf_sequence_prompt_led_off = {
    &message_blue_0, &message_do_not_reset, NULL,
};

static void zf_prompt_timer_callback(void *context) {
    UNUSED(context);
    uint32_t tick = zf_prompt_tick++;

    if (!zf_prompt_notifications) {
        return;
    }
    if (tick & 1U) {
        notification_message(zf_prompt_notifications, &zf_sequence_prompt_led_off);
    } else {
        notification_message(zf_prompt_notifications, &zf_sequence_prompt_led_on);
    }
    if ((tick & 1U) == 0U && tick / 2U < ZF_PROMPT_VIBRO_PULSES) {
        notification_message(zf_prompt_notifications, &zf_sequence_prompt_pulse);
    }
}

static void zf_prompt_stop(void) {
    if (zf_prompt_timer) {
        furi_timer_stop(zf_prompt_timer);
    }
}

static const NotificationSequence zf_sequence_idle_dark = {
    &message_red_0, &message_green_0, &message_blue_0, &message_do_not_reset, NULL,
};

static const NotificationSequence zf_sequence_idle_charging = {
    &message_red_255, &message_green_0, &message_blue_0, &message_do_not_reset, NULL,
};

static const NotificationSequence zf_sequence_idle_charged = {
    &message_red_0, &message_green_255, &message_blue_0, &message_do_not_reset, NULL,
};

/*
 * Resetting notifications returns LEDs to the idle charging/done/dark state
 * instead of just stopping blink sequences.
 */
static void zf_notify_apply_idle_state(ZerofidoApp *app, bool block) {
    const NotificationSequence *sequence = &zf_sequence_idle_dark;

    if (!app || !app->notifications) {
        return;
    }

    if (furi_hal_power_is_charging()) {
        if (furi_hal_power_get_pct() == 100 || furi_hal_power_is_charging_done()) {
            sequence = &zf_sequence_idle_charged;
        } else {
            sequence = &zf_sequence_idle_charging;
        }
    }

    if (block) {
        notification_message_block(app->notifications, sequence);
    } else {
        notification_message(app->notifications, sequence);
    }
}

static void zf_notify_clear(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return;
    }

    notification_message_block(app->notifications, &sequence_blink_stop);
    zf_notify_apply_idle_state(app, true);
}

static void zf_notify_clear_async(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return;
    }

    notification_message(app->notifications, &sequence_blink_stop);
    zf_notify_apply_idle_state(app, false);
}

static void zf_notify_timeout_callback(void *context) {
    ZerofidoApp *app = context;

    if (!app || !app->notifications) {
        return;
    }

    if (app->view_dispatcher && app->ui_mutex) {
        zerofido_ui_dispatch_custom_event(app, ZfEventNotificationTimeout);
    } else {
        zf_notify_clear_async(app);
    }
}

static void zf_notify_stop_timer(ZerofidoApp *app) {
    if (!app || !app->notify_timer) {
        return;
    }

    furi_timer_stop(app->notify_timer);
}

static void zf_notify_arm_clear(ZerofidoApp *app, uint32_t timeout_ms) {
    if (!app || !app->notify_timer) {
        return;
    }

    furi_timer_start(app->notify_timer, timeout_ms);
}

static bool zf_notify_should_vibrate(const ZerofidoApp *app) {
    return app && !app->transport_auto_accept_transaction;
}

static void zf_notify_prepare_transient(ZerofidoApp *app) {
    zf_prompt_stop();
    zf_notify_stop_timer(app);
    zf_notify_clear_async(app);
}

bool zerofido_notify_init(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return false;
    }

    app->notify_timer = furi_timer_alloc(zf_notify_timeout_callback, FuriTimerTypeOnce, app);
    if (!app->notify_timer) {
        return false;
    }
    zf_prompt_notifications = app->notifications;
    zf_prompt_timer = furi_timer_alloc(zf_prompt_timer_callback, FuriTimerTypePeriodic, NULL);

    zf_notify_apply_idle_state(app, true);
    return true;
}

void zerofido_notify_deinit(ZerofidoApp *app) {
    if (!app || !app->notify_timer) {
        return;
    }

    zf_prompt_stop();
    if (zf_prompt_timer) {
        furi_timer_free(zf_prompt_timer);
        zf_prompt_timer = NULL;
    }
    zf_notify_stop_timer(app);
    zf_notify_clear(app);
    zf_prompt_notifications = NULL;
    furi_timer_free(app->notify_timer);
    app->notify_timer = NULL;
}

void zerofido_notify_prompt(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return;
    }

    zf_notify_prepare_transient(app);
    notification_message(app->notifications, &sequence_display_backlight_on);
    if (zf_prompt_timer && zf_notify_should_vibrate(app)) {
        zf_prompt_tick = 0;
        zf_prompt_timer_callback(NULL); /* first pulse and light right away */
        furi_timer_start(zf_prompt_timer, ZF_PROMPT_TICK_MS);
    } else {
        notification_message(app->notifications, &sequence_blink_start_magenta);
    }
}

void zerofido_notify_wink(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return;
    }

    zf_notify_prepare_transient(app);
    notification_message(app->notifications, &sequence_blink_start_magenta);
    zf_notify_arm_clear(app, ZF_NOTIFY_WINK_MS);
}

void zerofido_notify_success(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return;
    }

    zf_notify_prepare_transient(app);
    if (zf_notify_should_vibrate(app)) {
        notification_message(app->notifications, &sequence_single_vibro);
    }
    notification_message(app->notifications, &sequence_set_green_255);
    zf_notify_arm_clear(app, ZF_NOTIFY_SUCCESS_MS);
}

void zerofido_notify_error(ZerofidoApp *app) {
    if (!app || !app->notifications) {
        return;
    }

    zf_notify_prepare_transient(app);
    if (zf_notify_should_vibrate(app)) {
        notification_message(app->notifications, &sequence_double_vibro);
    }
    notification_message(app->notifications, &sequence_set_red_255);
    zf_notify_arm_clear(app, ZF_NOTIFY_ERROR_MS);
}

void zerofido_notify_reset(ZerofidoApp *app) {
    zf_prompt_stop();
    zf_notify_stop_timer(app);
    zf_notify_clear(app);
}
