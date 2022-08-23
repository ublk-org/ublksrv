# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Originally from:
# https://github.com/WinterMute/prboom/blob/master/autotools/ac_c_compile_flags.m4
# RWMJ: I adapted it to add the extra parameters and fixed a few bugs.

# AC_C_COMPILE_FLAGS(VAR, FLAGS TO TEST, [CFLAGS_FOR_TEST = $CFLAGS])
# ----------------------------------------------------------
# Check if compiler flag $2 is supported, if so add it to $1.
# Extra CFLAGS for the test can be passed in $3.
AC_DEFUN([AC_C_COMPILE_FLAGS],[
    CFLAGS_FOR_TEST="m4_default([$3], [$CFLAGS])"
    for flag in $2
    do
        AC_MSG_CHECKING(whether the compiler supports $flag)
        SAVED_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS_FOR_TEST $flag"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM()
        ],[
            AC_MSG_RESULT(yes)
            $1="${$1} $flag"
        ],[AC_MSG_RESULT(no)])
        CFLAGS="$SAVED_CFLAGS"
    done
])
