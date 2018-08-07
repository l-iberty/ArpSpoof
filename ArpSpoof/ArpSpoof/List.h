#ifndef LIST_H
#define LIST_H

typedef unsigned int IPv4_ADDR;
typedef IPv4_ADDR ElemType;

#define NONE 0

typedef struct ListNode {
	ElemType e;
	struct ListNode * next;
} *List,*Position;

List		List_Create();
int			List_isEmpty(List _List);
int			List_Add(List _List, ElemType e);
Position	List_Find(List _List, ElemType e);
Position	List_FindPrev(List _List, ElemType e);
void		List_Delete(List _List, ElemType e);
void		List_Display(List _List);
void		List_Destory(List _List);

#endif // LIST_H