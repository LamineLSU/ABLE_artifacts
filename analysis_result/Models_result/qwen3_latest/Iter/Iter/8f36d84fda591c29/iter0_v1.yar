rule EvasionDetection {
    meta:
        description = "Detects evasion by early exit via specific instruction patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 83 C4 14 52 FF D0 5E 5D C3 }  // Function epilogue with early return
        $b = { 50 E8 ?? ?? ?? ?? 8B 45 ?? }  // Call to external function followed by register load
        $c = { 8B 55 0C 8B 06 83 C4 14 }  // Local variable access and stack adjustment
    condition:
        any of ($a, $b, $c)
}