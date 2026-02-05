rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 54 D3 FF FF }
        $pattern1 = { 8B 45 FC ?? ?? ?? ?? 02 34 F6 CC 00 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}