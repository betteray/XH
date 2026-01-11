(function() {
    var HsXHPatientDetailViewController = ObjC.classes.HsXHPatientDetailViewController;
    
    if (HsXHPatientDetailViewController) {
        Interceptor.attach(HsXHPatientDetailViewController['- setDetailModel:'].implementation, {
            onEnter: function(args) {
                var model = new ObjC.Object(args[2]);
                
                console.log('\n========== HsXHPatientDetailModel ==========');
                console.log('patId:              ' + model.patId());
                console.log('patId32:            ' + model.patId32());
                console.log('patName:            ' + model.patName());
                console.log('chnName:            ' + model.chnName());
                console.log('cardNo:             ' + model.cardNo());
                console.log('cardNoType:         ' + model.cardNoType());
                console.log('cardNoTypeDesc:     ' + model.cardNoTypeDesc());
                console.log('phoneNo:            ' + model.phoneNo());
                console.log('documentId:         ' + model.documentId());
                console.log('relation:           ' + model.relation());
                console.log('authStatus:         ' + model.authStatus());
                console.log('authStatusDesc:     ' + model.authStatusDesc());
                console.log('accessPatId:        ' + model.accessPatId());
                console.log('isDelete:           ' + model.isDelete());
                console.log('hasCanFaceAuth:     ' + model.hasCanFaceAuth());
                console.log('hasShowFaceAuthButton: ' + model.hasShowFaceAuthButton());
                console.log('medInsCardNo:       ' + model.medInsCardNo());
                console.log('=============================================\n');
            }
        });
        
        console.log('[+] Hooked HsXHPatientDetailViewController setDetailModel:');
    } else {
        console.log('[-] HsXHPatientDetailViewController not found');
    }
})();