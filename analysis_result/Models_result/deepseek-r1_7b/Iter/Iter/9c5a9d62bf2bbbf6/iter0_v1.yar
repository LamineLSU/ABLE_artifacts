rule Bypass_Evasion {
    meta:
        description = "Detects bypassed anti-debugging exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 C8 FF FF FF } // Pushes ebp and sets up call
        $pattern1 = { 55 8B FC 4D F3 FD 6A 8B CA } // Uses different registers for setup
        $pattern2 = { 55 8B FB FF E8 C8 FF FF FF } // Alternative setup leading to same exit
    condition:
        any of them
}