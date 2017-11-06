defmodule U do
  use Bitwise

  def replicate(n, x) when is_number(x) do
    for _ <- 1..n, do: x 
  end
  def replicate(n, s) when is_bitstring(s) do
  	Enum.map_join(1..n, fn _ -> s end)
  end

  @doc """
    `rem` is not exactly as the modulo when negative numbers is involved,
    so define the `mod` here

    iex> C.mod(-9, 19)
    10
    iex> rem(-9, 19)
    -9
  """
  def mod(0, _), do: 0
  def mod(x, y) when x > 0, do: rem(x, y)
  def mod(x, y) when x < 0, do: y + rem(x, y)

  @doc """
  built-in power loses accuracy due to float number conversion.
  integer positive integer power 

  TODO: native impl
  """
  @spec power(non_neg_integer, non_neg_integer) :: pos_integer
  def power(0, _), do: 1
  def power(1, _), do: 1
  def power(n, p) when p >= 0 and n >= 0 do
    _power(n, p, 1)
  end

  @doc """
  Python's pow(n, p, m) = (n ^ p) % m 
  """
  @spec power(non_neg_integer, non_neg_integer, non_neg_integer) :: non_neg_integer
  def power(n, p, modulo) when p >= 0 and n > 0 do
	_power(n, p, modulo, 1)	  		
  end

  defp _power(_, 0, accum), do: accum
  defp _power(n, p, accum) do
    _power(n, p-1, n*accum)
  end

  defp _power(_, 0, _, accum), do: accum
  defp _power(n, p, modulo, accum) do
  	accum = case p &&& 1 do
  	  0 ->
  	  	accum
  	  1 -> 
  	    mod(accum * n, modulo)
  	end
  	_power(mod(n * n, modulo), p >>> 1, modulo, accum)
  end
end