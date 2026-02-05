rule Bypass_Evasion
{
    meta:
        description = "Malware bypass of exit process using conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { BA 21 05 00 00 E8 E3 F9 ?? ?? ?? ?? 0F 84 }

    condition:
        any of them
}