rule Bypass_Evasion {
    meta:
        description = "Evasion bypass for exit process calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 ?? ?? ?? ?? ?? 8B 45 }  // Skipping first function call
        $pattern1 = { FF 75 08 ?? ?? ?? ?? }  // Skipping second function call
        $pattern2 = { 8B EC ?? ?? ?? ?? FF 75 08 }  // Exploiting dword ptr offset
}

condition:
    any_of($pattern0, $pattern1, $pattern2)