// Query hooks for contacts, contact roles, contact assignments and image
// attachments (DCIM BUILD_PLAN row 2.8). Every path is in the inventory-service
// spec (`/dcim/...`) and goes through the generated client; the reusable
// panels (<ObjectContacts>, <ObjectImages>) and Settings → Contacts share them.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError, substrateKeys } from './substrate-queries';

type S = components['schemas'];
export type Contact = S['Contact'];
export type ContactRole = S['ContactRole'];
export type ContactAssignment = S['ContactAssignment'];
export type ImageAttachment = S['ImageAttachment'];
export type ContactPriority = NonNullable<ContactAssignment['priority']>;

export const PRIORITIES: ContactPriority[] = ['primary', 'secondary', 'tertiary', 'inactive'];
export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
export const IMAGE_ACCEPT = 'image/png,image/jpeg,image/webp,image/svg+xml';

export const contactKeys = {
  contacts: () => ['dcim-contacts'] as const,
  roles: () => ['dcim-contact-roles'] as const,
  object: (kind: ObjectKind, id: string) => ['dcim-object-contacts', kind, id] as const,
  images: (kind: ObjectKind, id: string) => ['dcim-object-images', kind, id] as const,
};

/** The URL an <img> loads an attachment from (same origin, cookie auth). */
export function imageUrl(id: string): string {
  return `/api/v2/inventory-service/dcim/images/${id}/download`;
}

export function useContacts(enabled = true) {
  return useQuery({
    queryKey: contactKeys.contacts(),
    enabled,
    queryFn: async (): Promise<Contact[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/contacts', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load contacts'));
      return data.data ?? [];
    },
  });
}

export function useContactRoles(enabled = true) {
  return useQuery({
    queryKey: contactKeys.roles(),
    enabled,
    queryFn: async (): Promise<ContactRole[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/contact-roles', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load contact roles'));
      return data.data ?? [];
    },
  });
}

/** The contacts assigned to one object (contact and role inlined). */
export function useObjectContacts(kind: ObjectKind, id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: contactKeys.object(kind, id ?? ''),
    enabled: !!id && enabled,
    queryFn: async (): Promise<ContactAssignment[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/objects/{kind}/{id}/contacts', {
        params: { path: { kind, id: id! }, query: { limit: 200 } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load contacts'));
      return data.data ?? [];
    },
  });
}

export interface AssignInput { contact_id: string; role_id: string; priority?: ContactPriority | null }

export function useAssignContact(kind: ObjectKind, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: AssignInput): Promise<ContactAssignment> => {
      const { data, error } = await clients.inventory.POST('/dcim/objects/{kind}/{id}/contacts', {
        params: { path: { kind, id } },
        body: input,
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to assign the contact'));
      return data.data;
    },
    onSuccess: () => toast.success('Contact assigned'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to assign the contact'),
    onSettled: () => Promise.all([
      qc.invalidateQueries({ queryKey: contactKeys.object(kind, id) }),
      qc.invalidateQueries({ queryKey: substrateKeys.changes(kind, id) }),
    ]),
  });
}

export function useRemoveAssignment(kind: ObjectKind, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (assignmentId: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/contact-assignments/{id}', { params: { path: { id: assignmentId } } });
      if (error) throw new Error(substrateError(error, 'Failed to remove the contact'));
    },
    onSuccess: () => toast.success('Contact removed'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to remove the contact'),
    onSettled: () => Promise.all([
      qc.invalidateQueries({ queryKey: contactKeys.object(kind, id) }),
      qc.invalidateQueries({ queryKey: substrateKeys.changes(kind, id) }),
    ]),
  });
}

export interface ContactInput {
  name: string;
  title?: string | null;
  phone?: string | null;
  email?: string | null;
  address?: string | null;
  link?: string | null;
  group_id?: string | null;
  description?: string | null;
}

export function useContactWrite() {
  const qc = useQueryClient();
  const done = () => Promise.all([qc.invalidateQueries({ queryKey: contactKeys.contacts() }), qc.invalidateQueries({ queryKey: ['dcim-object-contacts'] })]);
  return {
    create: useMutation({
      mutationFn: async (body: ContactInput): Promise<Contact> => {
        const { data, error } = await clients.inventory.POST('/dcim/contacts', { body });
        if (error || !data) throw new Error(substrateError(error, 'Failed to create the contact'));
        return data.data;
      },
      onSettled: done,
    }),
    update: useMutation({
      mutationFn: async ({ id, body }: { id: string; body: Partial<ContactInput> }): Promise<Contact> => {
        const { data, error } = await clients.inventory.PATCH('/dcim/contacts/{id}', { params: { path: { id } }, body });
        if (error || !data) throw new Error(substrateError(error, 'Failed to save the contact'));
        return data.data;
      },
      onSettled: done,
    }),
    remove: useMutation({
      mutationFn: async (id: string): Promise<void> => {
        const { error } = await clients.inventory.DELETE('/dcim/contacts/{id}', { params: { path: { id } } });
        if (error) throw new Error(substrateError(error, 'Failed to delete the contact'));
      },
      onSettled: done,
    }),
  };
}

export function useContactRoleWrite() {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: contactKeys.roles() });
  return {
    create: useMutation({
      mutationFn: async (body: { name: string; slug?: string; description?: string | null }): Promise<ContactRole> => {
        const { data, error } = await clients.inventory.POST('/dcim/contact-roles', { body });
        if (error || !data) throw new Error(substrateError(error, 'Failed to create the role'));
        return data.data;
      },
      onSettled: done,
    }),
    update: useMutation({
      mutationFn: async ({ id, body }: { id: string; body: { name?: string; slug?: string; description?: string | null } }): Promise<ContactRole> => {
        const { data, error } = await clients.inventory.PATCH('/dcim/contact-roles/{id}', { params: { path: { id } }, body });
        if (error || !data) throw new Error(substrateError(error, 'Failed to save the role'));
        return data.data;
      },
      onSettled: done,
    }),
    remove: useMutation({
      mutationFn: async (id: string): Promise<void> => {
        const { error } = await clients.inventory.DELETE('/dcim/contact-roles/{id}', { params: { path: { id } } });
        if (error) throw new Error(substrateError(error, 'Failed to delete the role'));
      },
      onSettled: done,
    }),
  };
}

/** The images attached to one object, newest first. */
export function useObjectImages(kind: ObjectKind, id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: contactKeys.images(kind, id ?? ''),
    enabled: !!id && enabled,
    queryFn: async (): Promise<ImageAttachment[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/objects/{kind}/{id}/images', {
        params: { path: { kind, id: id! }, query: { limit: 200 } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load images'));
      return data.data ?? [];
    },
  });
}

export function useUploadImage(kind: ObjectKind, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { file: File; description?: string; slot?: 'front' | 'rear' }): Promise<ImageAttachment> => {
      if (input.file.size > MAX_IMAGE_BYTES) throw new Error('The image is larger than 5 MB.');
      // Typed multipart: the contract types the parts; the serializer supplies
      // the real FormData so the browser sets the boundary.
      const { data, error } = await clients.inventory.POST('/dcim/objects/{kind}/{id}/images', {
        params: { path: { kind, id } },
        body: { file: '' },
        bodySerializer: () => {
          const fd = new FormData();
          fd.append('file', input.file);
          if (input.description) fd.append('description', input.description);
          if (input.slot) fd.append('slot', input.slot);
          return fd;
        },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to upload the image'));
      return data.data;
    },
    onSuccess: () => toast.success('Image uploaded'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to upload the image'),
    onSettled: () => Promise.all([
      qc.invalidateQueries({ queryKey: contactKeys.images(kind, id) }),
      qc.invalidateQueries({ queryKey: substrateKeys.changes(kind, id) }),
      // A device type's front/rear ref moved with the upload.
      qc.invalidateQueries({ queryKey: ['dcim-catalogue'] }),
    ]),
  });
}

export function useDeleteImage(kind: ObjectKind, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (imageId: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/images/{id}', { params: { path: { id: imageId } } });
      if (error) throw new Error(substrateError(error, 'Failed to delete the image'));
    },
    onSuccess: () => toast.success('Image deleted'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the image'),
    onSettled: () => Promise.all([
      qc.invalidateQueries({ queryKey: contactKeys.images(kind, id) }),
      qc.invalidateQueries({ queryKey: substrateKeys.changes(kind, id) }),
      qc.invalidateQueries({ queryKey: ['dcim-catalogue'] }),
    ]),
  });
}
