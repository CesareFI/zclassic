/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Export the real wallet GUI entry under a name the headless
 * loader can resolve without calling itself.
 */
int wallet_gui_main(int argc, char **argv, const char *datadir);

int z23_wallet_gui_main(int argc, char **argv, const char *datadir)
{
    return wallet_gui_main(argc, argv, datadir);
}
