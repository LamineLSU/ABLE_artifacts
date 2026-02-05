rule Bypass_Sample_TestInstruction
{
    meta:
        description = "Evasion bypass rule - Skipping the Test Instruction"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 4E 4E 01 18 7B 4D 55 55 8B EC 8B 45 08 }

    condition:
        all of them
}