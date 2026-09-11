from ersec_metamorphic import evaluate, VERSION
def test_metamorphic_pass_and_missing_is_not_pass():
 r=evaluate({'relations':[{'id':'a','type':'equal','baseline':'x','transformed':'y'},{'id':'b','type':'equal','baseline':'missing','transformed':'y'}],'observations':{'x':1,'y':1}})
 assert VERSION=='29.1.0'; assert r['counts']['pass']==1; assert r['counts']['not_tested']==1
def test_metamorphic_violation():
 r=evaluate({'relations':[{'id':'a','type':'different','baseline':'x','transformed':'y'}],'observations':{'x':1,'y':1}})
 assert r['counts']['violation']==1
