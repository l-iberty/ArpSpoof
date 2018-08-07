#include "List.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

List List_Create()
{
	List _List;
	_List = (List)malloc(sizeof(struct ListNode));
	_List->e = NONE;
	_List->next = NULL;

	return _List;
}

int List_isEmpty(List _List)
{
	return _List->next == NULL;
}

int List_Add(List _List, ElemType e)
{
	List NewNode;
	Position P;

	for (P = _List; P; P = P->next)
	{
		if (P->e == e)
			return 0; // Element already exists.
		if (P->next == NULL)
			break;
	}

	NewNode = (List)malloc(sizeof(struct ListNode));
	NewNode->e = e;
	NewNode->next = NULL;
	P->next = NewNode;
	return 1;
}

Position List_Find(List _List, ElemType e)
{
	Position Prev;
	Prev = List_FindPrev(_List, e);

	return Prev ? Prev->next : NULL;
}

Position List_FindPrev(List _List, ElemType e)
{
	Position P;

	for (P = _List;P->next && P->next->e != e;P = P->next);
	
	return P->next ? P : NULL;
}

void List_Delete(List _List, ElemType e)
{
	Position Prev, Next;

	Prev = List_FindPrev(_List, e);
	if (Prev != NULL)
	{
		Next = Prev->next->next;
		free(Prev->next);
		Prev->next = Next;
	}
}

void List_Display(List _List)
{
	Position P;

	printf("\n");
	for (P = _List->next;P;P = P->next)
	{
		printf("%.8X ", P->e);
	}
	printf("\n");
}

void List_Destory(List _List)
{
	Position P, AfterP;
	for (P = _List;P;P = AfterP)
	{
		AfterP = P->next;
		free(P);
	}
}
