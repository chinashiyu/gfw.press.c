/**
 *
 *    GFW.Press
 *    Copyright (C) 2016  chinashiyu ( chinashiyu@gfw.press ; http://gfw.press )
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 **/

#include <stdio.h>
#include <stdlib.h>

extern int _start();

extern int load_config();

extern void _log(char *message);

int main(void) {

	_log("客户端开始运行......");

	if (load_config() != 0) {

		_log("配置错误，退出。");

		return -1;

	}

	_start();

	/**
	 while (1) {

	 sleep(7200);

	 _log("手里啊捧着窝窝头，菜里没有一点油，翻墙的日子是多么艰苦啊，转眼就过两个钟头......");

	 }
	 */

}
