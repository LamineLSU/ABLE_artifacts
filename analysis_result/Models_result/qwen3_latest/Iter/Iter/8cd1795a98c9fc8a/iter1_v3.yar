rule ProcessTerminationBehavior
{
    meta:
        description = "Detects potential process termination behavior via control flow obfuscation and system calls."
        cape_options = "bp0=$evasion_check+0,action0=skip,bp1=$bitwise_check+0,action1=skip,bp2=$terminate_call+0,action2=skip,count=0"

    strings:
        $evasion_check = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $bitwise_check = { C1 E8 08 A8 01 75 10 }
        $terminate_call = { FF 15 ?? F1 42 00 }

    condition:
        all of ($evasion_check, $bitwise_check, $terminate_call)
}