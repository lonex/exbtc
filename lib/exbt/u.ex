defmodule U do

  def replicate(n, x) do
    for _ <- 1..n, do: x 
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
  """
  @spec power(non_neg_integer, non_neg_integer) :: pos_integer
  def power(0, _), do: 1
  def power(1, _), do: 1
  def power(n, p) do
    _power(n, p, 1)
  end

  defp _power(_, 0, accum), do: accum
  defp _power(n, p, accum) do
    _power(n, p-1, n*accum)
  end
end