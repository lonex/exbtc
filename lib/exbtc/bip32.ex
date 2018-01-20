defmodule Exbtc.BIP32 do
  alias Exbtc.Core, as: C
  alias Exbtc.U

  @spec electrum_stretch(String.t()) :: charlist
  def electrum_stretch(seed) do
    C.slowsha(String.to_charlist(seed))
  end

  @spec electrum_mpk(String.t()) :: String.t()
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
  @spec electrum_privkey(String.t(), Integer, 0 | 1) :: String.t()
  def electrum_privkey(seed, n, for_change \\ 0) do
    seed =
      if String.length(seed) == 32 do
        electrum_stretch(seed)
      else
        seed
      end

    mpk = electrum_mpk(seed)
    {:ok, binary} = Base.decode16(mpk, case: :lower)

    offset =
      C.bin_double_sha256(
        Integer.to_charlist(n) ++
          [':'] ++ Integer.to_charlist(for_change) ++ [':'] ++ :binary.bin_to_list(binary)
      )

    C.add_privkeys(seed, offset)
  end

  @doc """
  master_key: can be seed, stetched seed or master public key
  """
  @spec electrum_pubkey(String.t(), Integer, 0 | 1) :: String.t()
  def electrum_pubkey(master_key, n, for_change \\ 0) do
    mpk =
      case String.length(master_key) do
        32 ->
          electrum_mpk(electrum_stretch(master_key))

        64 ->
          electrum_mpk(master_key)

        _ ->
          master_key
      end

    # our version of the C.encode_pubkey takes pair of integers, so C.decode_pubkey first
    bin_mpk = C.encode_pubkey(C.decode_pubkey(mpk), "bin_electrum")

    offset =
      C.bin_double_sha256(
        Integer.to_charlist(n) ++ [':'] ++ Integer.to_charlist(for_change) ++ [':'] ++ bin_mpk
      )

    C.add_pubkeys("04" <> mpk, C.privkey_to_pubkey(offset))
  end

  def electrum_address(master_key, n, for_change \\ 0, version \\ 0) do
    C.pubkey_to_address(electrum_pubkey(master_key, n, for_change), version)
  end

  @mainnet_private [4, 136, 173, 228]
  @mainnet_public [4, 136, 178, 30]
  @testnet_private [4, 53, 131, 148]
  @testnet_public [4, 53, 135, 207]
  @private [@mainnet_private, @testnet_private]
  @public [@mainnet_public, @testnet_public]

  @spec raw_bip32_ckd({charlist, Integer, charlist, Integer, charlist, charlist}, Integer) ::
          {charlist, charlist}
  def raw_bip32_ckd({vbytes, depth, fingerprint, _oldi, chaincode, key}, i) do
    {priv, pub} =
      if vbytes in @private do
        {key, C.privkey_to_pubkey(key)}
      else
        {nil, key}
      end

    cap_i =
      :binary.bin_to_list(
        if i >= U.power(2, 31) do
          if vbytes in @public do
            raise "Cannot do private derivation on public key"
          else
            :crypto.hmac(
              :sha512,
              chaincode,
              [0] ++ String.slice(priv, 0, 31) ++ C.encode(i, 256, 4)
            )
          end
        else
          :crypto.hmac(:sha512, chaincode, pub ++ C.encode(i, 256, 4))
        end
      )

    {newkey, fingerprint} =
      cond do
        vbytes in @private ->
          {C.add_privkeys(Enum.slice(cap_i, 0..31) ++ [1], priv),
           Enum.slice(C.bin_hash160(C.privkey_to_pubkey(key)), 0..3)}

        vbytes in @public ->
          {C.add_pubkeys(C.compress(C.privkey_to_pubkey(Enum.slice(cap_i, 0..31))), key),
           Enum.slice(C.bin_hash160(key), 0..3)}

        true ->
          {nil, fingerprint}
      end

    {vbytes, depth + 1, fingerprint, i, Enum.slice(cap_i, 32..length(cap_i)), newkey}
  end

  @spec bip32_serialize({charlist, Integer, charlist, Integer, charlist, charlist}) :: String.t()
  def bip32_serialize({vbytes, depth, fingerprint, i, chaincode, key}) do
    i = C.encode(i, 256, 4)
    chaincode = C.encode(C.hash_to_int(chaincode), 256, 32)

    keydata =
      if vbytes in @private do
        [0] ++ Enum.slice(key, 0..(length(key) - 2))
      else
        key
      end

    bindata = vbytes ++ [U.mod(depth, 256)] ++ fingerprint ++ i ++ chaincode ++ keydata
    (bindata ++ Enum.slice(C.bin_double_sha256(bindata), 0..3)) |> C.changebase(256, 58)
  end

  @spec bip32_deserialize(String.t()) ::
          {charlist, Integer, charlist, Integer, charlist, charlist}
  def bip32_deserialize(data) do
    bin = C.changebase(data, 58, 256)
    sha = Enum.slice(C.bin_double_sha256(Enum.slice(bin, 0..(length(bin) - 5))), 0..3)

    if sha != Enum.slice(bin, (length(bin) - 4)..length(bin)) do
      raise("Invalid checksum")
    end

    vbytes = Enum.slice(bin, 0..3)
    depth = Enum.at(bin, 4)
    fingerprint = Enum.slice(bin, 5..8)
    i = C.decode(Enum.slice(bin, 9..12), 256)
    chaincode = Enum.slice(bin, 13..44)

    key =
      if vbytes in @private do
        Enum.slice(bin, 46..77) ++ [1]
      else
        Enum.slice(bin, 45..77)
      end

    {vbytes, depth, fingerprint, i, chaincode, key}
  end

  @spec bip32_ckd(String.t(), Integer) :: String.t()
  def bip32_ckd(data, i) do
    raw_bip32_ckd(bip32_deserialize(data), i) |> bip32_serialize
  end

  def raw_bip32_privtopub({vbytes, depth, fingerprint, i, chaincode, key}) do
    new_vbytes =
      if vbytes == @mainnet_private do
        @mainnet_public
      else
        @testnet_public
      end

    {new_vbytes, depth, fingerprint, i, chaincode, C.privkey_to_pubkey(key)}
  end

  def bip32_privtopub(data) do
    raw_bip32_privtopub(bip32_deserialize(data)) |> bip32_serialize
  end

  @spec bip32_master_key(String.t(), charlist) :: String.t()
  def bip32_master_key(seed, vbytes \\ @mainnet_private) do
    cap_i =
      :binary.bin_to_list(
        :crypto.hmac(
          :sha512,
          C.from_string_to_bytes("Bitcoin seed"),
          C.from_string_to_bytes(seed)
        )
      )

    {vbytes, 0, U.replicate(4, 0), 0, Enum.slice(cap_i, 32..length(cap_i)),
     Enum.slice(cap_i, 0..31) ++ [1]}
    |> bip32_serialize
  end

  @spec bip32_bin_extract_key(String.t()) :: charlist
  def bip32_bin_extract_key(data) do
    t = bip32_deserialize(data)
    elem(t, tuple_size(t) - 1)
  end

  @spec bip32_extract_key(String.t()) :: Strint.t()
  def bip32_extract_key(data) do
    t = bip32_deserialize(data)
    elem(t, tuple_size(t) - 1) |> :binary.list_to_bin() |> C.bytes_to_hex_string()
  end
end
