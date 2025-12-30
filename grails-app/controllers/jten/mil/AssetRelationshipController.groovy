package jten.mil

import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

class AssetRelationshipController {
    def index() {
        List <AssetRelationship> assetRelationships = AssetRelationship.list()
        respond assetRelationships
    }

    def list() {
        ArrayList dataList = []
        List<AssetRelationship> results = AssetRelationship.list()
        results.each { AssetRelationship a ->
            dataList << [
                    a.name,
                    a.aor.name,
                    a.poc.name,
                    a.id
            ]
        }
        LinkedHashMap<String,ArrayList> data = ["data": dataList]
        respond data
    }

    def show(AssetRelationship assetRelationship) {
        respond assetRelationship
    }

    def create() {
        List<Aor> aors = Aor.list().sort{Aor it -> it.name}
        respond new AssetRelationship(params), model: [aors: aors]
    }

    @Transactional
    def save(AssetRelationship assetRelationship) {
        if (assetRelationship == null) {
            notFound()
            return
        }
        try {
            assetRelationship.save()
        } catch (ValidationException e) {
            log.error(e.getMessage())
            respond assetRelationship.errors, view: 'create'
        }
        respond assetRelationship, [status: CREATED, view:"show"]
    }

    def edit(AssetRelationship assetRelationship) {
        respond assetRelationship
    }

    @Transactional
    def update(AssetRelationship assetRelationship) {
        try {
            assetRelationship.save()
        } catch (ValidationException e) {
            e.suppressed
            respond assetRelationship.errors, view: 'edit'
        }
    }

    @Transactional
    def delete(AssetRelationship assetRelationship) {
        assetRelationship.delete()
        render "status: NO_CONTENT"
    }
}