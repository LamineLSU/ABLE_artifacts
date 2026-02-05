rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis for sandbox"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { BB 37 6D 9C A8 FF FE 7F EC EA FA FF FF 7C 40 FC 2C 9E 1E 00 }

    condition:
        any of them
}