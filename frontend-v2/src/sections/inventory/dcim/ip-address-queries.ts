// The IP Addresses tab's writes: an asset's primary IPv4, primary IPv6 and
// out-of-band address (PATCH /dcim/assets/{id}/primary-ips). The list itself is
// the IPAM list (`useIpamList('ip-addresses', { asset_id })`).
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { clients } from '../../../lib/clients';
import { ipamKeys } from '../ipam/ipam-queries';
import { substrateError } from './substrate-queries';

export type AssetIpField = 'primary_ip4_id' | 'primary_ip6_id' | 'oob_ip_id';

export function useSetAssetIp(assetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ field, addressId }: { field: AssetIpField; addressId: string | null }) => {
      const { data, error } = await clients.inventory.PATCH('/dcim/assets/{id}/primary-ips', {
        params: { path: { id: assetId } },
        body: { [field]: addressId },
      });
      if (error || !data) throw new Error(substrateError(error, 'Could not save the address'));
      return data.data;
    },
    onSuccess: (_d, v) => {
      toast.success(v.addressId ? 'Saved' : 'Cleared');
      void qc.invalidateQueries({ queryKey: ipamKeys.all });
    },
    onError: (e) => { toast.error(e instanceof Error ? e.message : 'Could not save the address'); },
  });
}
