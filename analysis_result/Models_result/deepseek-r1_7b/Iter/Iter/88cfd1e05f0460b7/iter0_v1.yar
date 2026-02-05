rule Bypass_Sample
{
    meta:
        description = "Bypass evasion at specific target addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? FF C8 ?? ?? ?? }  // Skipping push and pop around the call
        $pattern1 = { 6A 5A ?? FF 45 ?? ?? E8 F0 ?? ?? ?? }  // Skipping mov before a call
        $pattern2 = { FF 75 08 ?? FF C8 F3 FF C0 }  // Skipping multiple jumps to reach this call
}

    condition:
        any_of([$pattern0, $pattern1, $pattern2])
}