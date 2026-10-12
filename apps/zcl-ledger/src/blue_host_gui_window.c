/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_host_gui_window.h"

#include <gtk/gtk.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

enum { WINDOW_WIDTH = 320 };

static const char window_css[] =
    "window, box { background-color: #12161c; color: #f4f7f5; }\n"
    ".sheet { background-color: #12161c; }\n"
    ".kicker { color: #41ccb4; font-weight: 700; font-size: 10px; }\n"
    ".value { color: #f4f7f5; font-size: 13px; font-family: monospace; }\n"
    ".hero { color: #f7fbf9; font-size: 20px; font-weight: 700; }\n"
    ".signword { color: #f7fbf9; font-size: 15px; font-weight: 700; }\n"
    ".empty { color: #7d8b87; font-size: 13px; }\n"
    ".title { color: #f7fbf9; font-size: 16px; font-weight: 700; }\n"
    ".quiet { color: #9aa8a4; font-size: 11px; }\n"
    ".card { background-color: #1b242e; padding: 8px; border-radius: 10px; }\n";

static void style_window(GtkWidget *window) {
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, window_css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gtk_widget_get_screen(window), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
}

static void class_label(GtkWidget *label, const char *name, float align) {
    gtk_label_set_xalign(GTK_LABEL(label), align);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(label), name);
}

static GtkWidget *card(const char *kicker, const char *value,
                      const char *value_class) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    GtkWidget *kick = gtk_label_new(kicker);
    GtkWidget *body = gtk_label_new(value);
    class_label(kick, "kicker", 0);
    class_label(body, value_class, 0);
    gtk_label_set_max_width_chars(GTK_LABEL(body), 24);
    gtk_box_pack_start(GTK_BOX(box), kick, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), body, FALSE, FALSE, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(box), "card");
    return box;
}

static const char *memo_class(const char *memo) {
    return strcmp(memo, "NO MEMO") == 0 ? "empty" : "value";
}

static GtkWidget *payment_sheet(const blue_host_gui_facts *facts) {
    char identity[80];
    GtkWidget *sheet = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *title = gtk_label_new("Z23");
    GtkWidget *who;
    GtkWidget *link = gtk_label_new(facts->connection);
    GtkWidget *note = gtk_label_new(
        "Matches the Blue. Does not sign or install.");
    snprintf(identity, sizeof identity, "%s  ·  %s",
             facts->app_name, facts->app_version);
    who = gtk_label_new(identity);
    gtk_widget_set_margin_top(sheet, 10);
    gtk_widget_set_margin_bottom(sheet, 10);
    gtk_widget_set_margin_start(sheet, 10);
    gtk_widget_set_margin_end(sheet, 10);
    class_label(title, "title", 0);
    class_label(who, "quiet", 0);
    class_label(link, "quiet", 0);
    class_label(note, "quiet", 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(sheet), "sheet");
    gtk_box_pack_start(GTK_BOX(sheet), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet), who, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet), link, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet), note, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet),
                       card("RECEIVE", facts->receive, "value"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet),
                       card("PAY TO", facts->recipient, "value"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet),
                       card("AMOUNT", facts->amount, "hero"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet), card("FEE", facts->fee, "value"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet),
                       card("NETWORK", facts->network, "value"),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet),
                       card("MEMO", facts->memo, memo_class(facts->memo)),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sheet),
                       card("APPROVAL", facts->approval, "signword"),
                       FALSE, FALSE, 0);
    return sheet;
}

static void fit_window(GtkWidget *window, GtkWidget *sheet) {
    int height = 0;
    gtk_widget_get_preferred_height_for_width(sheet, WINDOW_WIDTH, NULL,
                                              &height);
    if (height < 280) height = 280;
    gtk_widget_set_size_request(window, WINDOW_WIDTH, height);
    gtk_window_set_default_size(GTK_WINDOW(window), WINDOW_WIDTH, height);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
}

static void paint(GtkWidget *window, GtkWidget *sheet) {
    style_window(window);
    gtk_container_add(GTK_CONTAINER(window), sheet);
    fit_window(window, sheet);
    gtk_widget_show_all(window);
    while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
}

static bool save_shot(GtkWidget *window, const char *path) {
    GdkWindow *gdk = gtk_widget_get_window(window);
    int width = gtk_widget_get_allocated_width(window);
    int height = gtk_widget_get_allocated_height(window);
    GdkPixbuf *image;
    GError *error = NULL;
    if (!gdk || width < 32 || height < 32) return false;
    image = gdk_pixbuf_get_from_window(gdk, 0, 0, width, height);
    if (!image) return false;
    bool saved = gdk_pixbuf_save(image, path, "png", &error, NULL);
    g_object_unref(image);
    if (error) g_error_free(error);
    return saved;
}

int blue_host_gui_present(const blue_host_gui_facts *facts,
                          const char *shot_path) {
    GtkWidget *window;
    GtkWidget *sheet;
    if (!facts || !gtk_init_check(NULL, NULL)) return 3;
    sheet = payment_sheet(facts);
    if (shot_path) {
        window = gtk_offscreen_window_new();
        paint(window, sheet);
        bool saved = save_shot(window, shot_path);
        gtk_widget_destroy(window);
        return saved ? 0 : 1;
    }
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Z23 Blue");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    paint(window, sheet);
    gtk_main();
    return 0;
}
