#ifndef LIST_H
#define LIST_H
#include "type.h"

#define NONE	{ 0 }
#define MAC_LEN	6

typedef struct addr_entry ListElement;

typedef struct ListNode
{
	ListElement e;
	struct ListNode * next;
} *List,*Position;

List		List_Create();
int			List_isEmpty(List L);
int			List_Add(List L, ListElement e);
Position	List_Find(List L, ListElement e);
Position	List_FindPrev(List L, ListElement e);
void		List_Delete(List L, ListElement e);
void		List_Display(List L);
void		List_Destory(List L);

#endif // LIST_H