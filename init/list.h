/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
 
//头文件一般这么写，以免文件很多的时候被包含多次而报错
#ifndef _INIT_LIST_H_
#define _INIT_LIST_H_


//链表节点，并不存储业务内容，只负责构建链表，最终构建带业务逻辑的链表的时候，只需要在业务逻辑的节点里面加上一个listnode的字段，然后listnode构成链表，再通过指针运算就可以寻找到业务节点，业务节点是间接构成链表的
struct listnode
{
    struct listnode *next;
    struct listnode *prev;
};

//定义宏，通过指针运算，将链表节点的指针转换成业务节点指针
#define node_to_item(node, container, member) \
    (container *) (((char*) (node)) - offsetof(container, member))

//声明链表节点
#define list_declare(name) \
    struct listnode name = { \
        .next = &name, \
        .prev = &name, \
    }
//for循环的简写宏，宏在预处理阶段就会替换的，
#define list_for_each(node, list) \
    for (node = (list)->next; node != (list); node = node->next)

//反向遍历链表
#define list_for_each_reverse(node, list) \
    for (node = (list)->prev; node != (list); node = node->prev)

void list_init(struct listnode *list);
void list_add_tail(struct listnode *list, struct listnode *item);
void list_remove(struct listnode *item);

#define list_empty(list) ((list) == (list)->next)
#define list_head(list) ((list)->next)
#define list_tail(list) ((list)->prev)

#endif
