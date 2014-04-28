
#ifndef CONSOLE_H
#define CONSOLE_H

#include "iw.h"
#include "ap_list.h"


void clear_scr();
void update_scr(struct ap_list *apl, struct iw_dev *dev);

#define RED_COLOR	"\033[1;31m"
#define RESET_COLOR	"\033[0m"

#endif
