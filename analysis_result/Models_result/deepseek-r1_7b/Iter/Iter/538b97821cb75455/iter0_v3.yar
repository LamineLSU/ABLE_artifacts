rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F FF 7F ?? ?? }
        $pattern1 = { E8 FF 7F ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }
    condition:
        any of them
}