rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass detection rules for a sample malware"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { BA D8 F6 88 02 8D 85 4C F2 FF FF EA EA DD EB 00 00 0D B4 ?? ?? 8B 85 4C F2 FF FF EA DD EB 00 00 0D B4 ?? ?? E8 72 E5 FF FF CA 02 87 4A 98 ?? ?? }
        $pattern2 = { 8D 85 4F 1F ?? EA DD EB 00 00 0D BC ?? ?? BA D8 F6 88 02 8D 85 4F 1F ?? EA EA DD EB 00 00 0D BC ?? ?? E8 72 E5 FF FF CA 02 87 4A 98 ?? ?? }

    condition:
        any of them
}