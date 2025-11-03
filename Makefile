INC_DIR		:= include
INC_FLAGS	:= -I $(INC_DIR)

OBJ_DIR		:= obj

SRCS		:= echo.c \
			   exec.c \
			   icmp.c \
			   ping.c \
			   utils.c

OBJS		:= $(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))
DEPS		:= $(OBJS:.o=.d)
CFLAGS	:=  -MMD -Wall -Wextra -Werror
LDFLAGS :=

NAME		:= ft_ping

.PHONY: all clean fclean re debug

all: CFLAGS += -O2
all: $(NAME)

debug: CFLAGS += -g -fsanitize=address -fno-omit-frame-pointer -O0
debug: LDFLAGS += -fsanitize=address
debug: fclean $(NAME)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: src/%.c
	gcc $(CFLAGS) $(INC_FLAGS) -o $@ -c $<

-include $(DEPS)

$(NAME): $(OBJ_DIR) $(OBJS)
	gcc $(LDFLAGS) -o $(NAME) $(OBJS)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

