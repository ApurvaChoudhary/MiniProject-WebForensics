
This repository contains (sometimes partial) re-implementations of the technologies involved in reading IndexedDB data 
in Chrome-esque applications.
This includes:
* Snappy decompression
* LevelDB
* V8 object deserialization
* Blink object deserialization
* IndexedDB wrapper


Read a blog on the subject here: https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium


There is a fair amount of work yet to be done in terms of documentation, but 
the modules should be fine for pulling data out of IndexedDB, with the following
caveats:


The LevelDB module will spit out live and deleted/old versions of records
indiscriminately; it's possible to differentiate between them with some
work, but that hasn't really been baked into the modules as they currently
stand. So you are getting deleted data "for free" currently...whether you
want it or not.


I am fairly satisfied that all the possible V8 object types are accounted for
(but I'm happy to be shown otherwise and get that fixed of course!), but it
is likely that the hosted Blink objects aren't all there yet; so if you hit
upon an error coming from inside ccl_blink_value_deserializer and can point
me towards test data, I'd be very thankful!


It is noted in the V8 source that recursive referencing is possible in the
serialization, we're not yet accounting for that so if Python throws a
`RecursionError` that's likely what you're seeing. The plan is to use a 
similar approach to ccl_bplist where the collection types are subclassed and
do Just In Time resolution of the items, but that isn't done yet.


There are two methods for accessing records - a more pythonic API using a set of 
wrapper objects and a raw API which doesn't mask the underlying workings. There is
unlikely to be much benefit to using the raw API in most cases, so the wrapper objects
are recommended in most cases.


```python
import sys
import ccl_chromium_indexeddb


leveldb_folder_path = sys.argv[1]
blob_folder_path = sys.argv[2]


wrapper = ccl_chromium_indexeddb.WrappedIndexDB(leveldb_folder_path, blob_folder_path)




db = wrapper[2]  
db = wrapper["MyTestDatabase"]  
db = wrapper["MyTestDatabase", "file__0@1"]  







obj_store = db[1]  
obj_store = db["store"]  


for record in obj_store.iterate_records():
    print(record.key)
    print(record.value)

    
    
    
    with record.get_blob_stream(record.value["file"]) as f:
        file_data = f.read()

```


```python
import sys
import ccl_chromium_indexeddb


leveldb_folder_path = sys.argv[1]
blob_folder_path = sys.argv[2]


db = ccl_chromium_indexeddb.IndexedDb(leveldb_folder_path, blob_folder_path)



for db_id_meta in db.global_metadata.db_ids:
    
    
    
    max_objstore_id = db.get_database_metadata(
            db_id_meta.dbid_no, 
            ccl_chromium_indexeddb.DatabaseMetadataType.MaximumObjectStoreId)
    
    
    if max_objstore_id is None:
        continue

    
    
    
    for obj_store_id in range(1, max_objstore_id + 1):
        
        
        for record in db.iterate_records(db_id_meta.dbid_no, obj_store_id):
            print(f"key: {record.key}")
            print(f"key: {record.value}")

            
            
            
            with record.get_blob_stream(record.value["file"]) as f:
                file_data = f.read()
```

