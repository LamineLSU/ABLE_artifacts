rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  // Bypass test eax by skipping the next conditional jump
        $pattern1 = { 6A ?? 5A 8B CE E8 CE ?? ?? ?? }  // Skip call to dword ptr with displacement [00C0E13Ch]
        $pattern2 = { FF 15 AC B0 41 00 ?? ?? ?? ?? }  // Bypass conditional jump or call instruction
}

condition:
    any of them
}