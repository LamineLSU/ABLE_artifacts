rule AntiTamperBypass
{
    meta:
        description = "Detects and bypasses anti-tamper checks and exit logic"
        cape_options = "bp0=$evasion_check+0,action0=skip,bp1=$post_check+0,action1=skip,bp2=$exit_call+0,action2=skip,count=0"
        confidence = 100

    strings:
        $evasion_check = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $post_check = { C1 E8 08 A8 01 75 10 }
        $exit_call = { FF 15 A0 F1 42 00 }

    condition:
        all of them
}