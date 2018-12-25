#include "List.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

List List_Create()
{
	List L;
	L = (List)malloc(sizeof(struct ListNode));
	L->e = NONE;
	L->next = NULL;

	return L;
}

int List_isEmpty(List L)
{
	return L->next == NULL;
}

int List_Add(List L, ListElement e)
{
	List NewNode;
	Position P;

	for (P = L; P; P = P->next)
	{
		if (P->e.ipv4 == e.ipv4)
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

Position List_Find(List L, ListElement e)
{
	Position Prev;
	Prev = List_FindPrev(L, e);

	return Prev ? Prev->next : NULL;
}

Position List_FindPrev(List L, ListElement e)
{
	Position P;

	for (P = L;
		P->next && P->next->e.ipv4 != e.ipv4;
		P = P->next);

	return P->next ? P : NULL;
}

void List_Delete(List L, ListElement e)
{
	Position Prev, Next;

	Prev = List_FindPrev(L, e);
	if (Prev != NULL)
	{
		Next = Prev->next->next;
		free(Prev->next);
		Prev->next = Next;
	}
}

void List_Display(List L)
{
	Position P;

	printf("\n");
	for (P = L->next; P; P = P->next)
	{
		printf("%.8X ", P->e.ipv4);
	}
	printf("\n");
}

void List_Destory(List L)
{
	Position P, AfterP;
	for (P = L; P; P = AfterP)
	{
		AfterP = P->next;
		free(P);
	}
}
