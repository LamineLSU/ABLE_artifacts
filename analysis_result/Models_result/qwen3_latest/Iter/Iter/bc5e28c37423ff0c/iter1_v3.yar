rule EvasionCheck1 {
    meta:
        description = "Conditional jump to ExitProcess based on EAX"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
    condition:
        $a
}