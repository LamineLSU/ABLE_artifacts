rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$B8F4C15F00000000+0,action0=skip,bp1=EC62D7BE00000000+0,action1=skip,bp2=8BD0301A00000000+0,action2=skip,count=0"

    strings:
        $B8F4C15F00000000 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $EC62D7BE00000000 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $8BD0301A00000000 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}