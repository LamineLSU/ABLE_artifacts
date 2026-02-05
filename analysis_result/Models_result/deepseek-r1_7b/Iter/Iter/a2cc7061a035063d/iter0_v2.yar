rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 C1 FF FF FF }
        $pattern1 = { FF 15 } (another call variant)
        $pattern2 = { 6A ?? 5A 8B CE E8 FF 15 } (longer pattern combining multiple instructions)

    condition:
        any of them
}