defmodule Exbtc.BIP32 do 
  alias Exbtc.Core, as: C

  @spec electrum_stretch(String.t) :: charlist
  def electrum_stretch(seed) do
    C.slowsha(String.to_charlist(seed))
  end

  @spec electrum_mpk(String.t) :: String.t
  def electrum_mpk(seed) do
    cond do
      String.length(seed) == 32 ->
        pubkey = C.privkey_to_pubkey(electrum_stretch(seed))
        String.slice(pubkey, 2..String.length(pubkey))
      true ->
        pubkey = C.privkey_to_pubkey(seed)
        String.slice(pubkey, 2..String.length(pubkey))
    end
  end

  @doc """
  for_change 0 ordinary address
             1 for change
  """
  @spec electrum_privkey(String.t, Integer, 0 | 1) :: String.t
  def electrum_privkey(seed, n, for_change \\ 0) do
    seed = if String.length(seed) == 32 do
      electrum_stretch(seed)
    else 
      seed
    end
    mpk = electrum_mpk(seed)
    {:ok, binary} = Base.decode16(mpk, case: :lower)
    offset = C.bin_double_sha256(Integer.to_charlist(n) ++ [ ':' ] ++ Integer.to_charlist(for_change) ++ [ ':' ] ++ :binary.bin_to_list(binary))
    C.add_privkeys(seed, offset)
  end

  @doc """
  master_key: can be seed, stetched seed or master public key
  """
  @spec electrum_pubkey(String.t, Integer, 0 | 1) :: String.t
  def electrum_pubkey(master_key, n, for_change \\ 0) do
    mpk = case String.length(master_key) do
      32 -> 
        electrum_mpk(electrum_stretch(master_key))
      64 -> 
        electrum_mpk(master_key)
      _ -> 
        master_key
    end
    # our version of the C.encode_pubkey takes pair of integers, so C.decode_pubkey first
    bin_mpk = C.encode_pubkey(C.decode_pubkey(mpk), "bin_electrum")
    offset = C.bin_double_sha256(Integer.to_charlist(n) ++ [ ':' ] ++ Integer.to_charlist(for_change) ++ [ ':' ] ++ bin_mpk)
    C.add_pubkeys("04" <> mpk, C.privkey_to_pubkey(offset))    
  end

  def electrum_address(master_key, n, for_change \\ 0, version \\ 0) do
    C.pubkey_to_address(electrum_pubkey(master_key, n, for_change), version)
  end

end
