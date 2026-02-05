rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection based on exit process calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE E8 ?? } <!-- TEST EAX, JE, POP, PUSH, and call -->
        $pattern1 = { BA 04 01 00 ?? ?? 6A 5B 8B ?? E8 ?? F0 ?? } <!-- PUSH EB, call with offset, then pop and add -->
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } <!-- PUSH 5B, POP EDX, move to ESI, call, TEST EAX -->

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}