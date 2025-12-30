package jten.mil

class StigItemCheckController {
	
    def index() {
        respond StigItemCheck.list()
    }
}
