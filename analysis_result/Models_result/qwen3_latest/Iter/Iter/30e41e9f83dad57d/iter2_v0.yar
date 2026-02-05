rule ObfuscatedControlFlow
{
    meta:
        description = "Detects obfuscated control flow patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        confidence = 85

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 75 07 }
        $pattern1 = { FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8B 45 F4 83 F8 11 74 05 }

    condition:
        any of ($pattern0, $pattern1, $pattern2)
}