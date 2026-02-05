rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 9D D9 01 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5A 8B CE E8 7E F2 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 83 C4 0D JZ 7C ?? ?? .8 B 1E 9E 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}