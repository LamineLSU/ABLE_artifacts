rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options Complexity = "High"

    strings:
        $a = { 93 7C ?? 8B 45 ?? }  // xchg + jl + mov (conditional jump context)
        $b = { 8B 45 ?? E8 ?? ?? ?? ?? }  // mov + call (data flow to external function)
        $c = { 52 FF D0 83 C4 04 8B 45 ?? }  // push + call + add + mov (stack manipulation)

    condition:
        all of them
}