




import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database


_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='site_data.proto',
  package='',
  syntax='proto2',
  serialized_options=_b('H\003'),
  serialized_pb=_b('\n\x0fsite_data.proto\"K\n\x14SiteDataFeatureProto\x12\x1c\n\x14observation_duration\x18\x01 \x01(\x03\x12\x15\n\ruse_timestamp\x18\x02 \x01(\x03\"r\n\x1eSiteDataPerformanceMeasurement\x12\x18\n\x10\x61vg_cpu_usage_us\x18\x01 \x01(\x02\x12\x18\n\x10\x61vg_footprint_kb\x18\x02 \x01(\x02\x12\x1c\n\x14\x61vg_load_duration_us\x18\x03 \x01(\x02\"\xe1\x02\n\rSiteDataProto\x12\x13\n\x0blast_loaded\x18\x01 \x01(\r\x12<\n\x1dupdates_favicon_in_background\x18\x02 \x01(\x0b\x32\x15.SiteDataFeatureProto\x12:\n\x1bupdates_title_in_background\x18\x03 \x01(\x0b\x32\x15.SiteDataFeatureProto\x12\x37\n\x18uses_audio_in_background\x18\x04 \x01(\x0b\x32\x15.SiteDataFeatureProto\x12J\n+deprecated_uses_notifications_in_background\x18\x05 \x01(\x0b\x32\x15.SiteDataFeatureProto\x12<\n\x13load_time_estimates\x18\x06 \x01(\x0b\x32\x1f.SiteDataPerformanceMeasurementB\x02H\x03')
)




_SITEDATAFEATUREPROTO = _descriptor.Descriptor(
  name='SiteDataFeatureProto',
  full_name='SiteDataFeatureProto',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='observation_duration', full_name='SiteDataFeatureProto.observation_duration', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='use_timestamp', full_name='SiteDataFeatureProto.use_timestamp', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=19,
  serialized_end=94,
)


_SITEDATAPERFORMANCEMEASUREMENT = _descriptor.Descriptor(
  name='SiteDataPerformanceMeasurement',
  full_name='SiteDataPerformanceMeasurement',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='avg_cpu_usage_us', full_name='SiteDataPerformanceMeasurement.avg_cpu_usage_us', index=0,
      number=1, type=2, cpp_type=6, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='avg_footprint_kb', full_name='SiteDataPerformanceMeasurement.avg_footprint_kb', index=1,
      number=2, type=2, cpp_type=6, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='avg_load_duration_us', full_name='SiteDataPerformanceMeasurement.avg_load_duration_us', index=2,
      number=3, type=2, cpp_type=6, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=96,
  serialized_end=210,
)


_SITEDATAPROTO = _descriptor.Descriptor(
  name='SiteDataProto',
  full_name='SiteDataProto',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='last_loaded', full_name='SiteDataProto.last_loaded', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='updates_favicon_in_background', full_name='SiteDataProto.updates_favicon_in_background', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='updates_title_in_background', full_name='SiteDataProto.updates_title_in_background', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='uses_audio_in_background', full_name='SiteDataProto.uses_audio_in_background', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='deprecated_uses_notifications_in_background', full_name='SiteDataProto.deprecated_uses_notifications_in_background', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='load_time_estimates', full_name='SiteDataProto.load_time_estimates', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=213,
  serialized_end=566,
)

_SITEDATAPROTO.fields_by_name['updates_favicon_in_background'].message_type = _SITEDATAFEATUREPROTO
_SITEDATAPROTO.fields_by_name['updates_title_in_background'].message_type = _SITEDATAFEATUREPROTO
_SITEDATAPROTO.fields_by_name['uses_audio_in_background'].message_type = _SITEDATAFEATUREPROTO
_SITEDATAPROTO.fields_by_name['deprecated_uses_notifications_in_background'].message_type = _SITEDATAFEATUREPROTO
_SITEDATAPROTO.fields_by_name['load_time_estimates'].message_type = _SITEDATAPERFORMANCEMEASUREMENT
DESCRIPTOR.message_types_by_name['SiteDataFeatureProto'] = _SITEDATAFEATUREPROTO
DESCRIPTOR.message_types_by_name['SiteDataPerformanceMeasurement'] = _SITEDATAPERFORMANCEMEASUREMENT
DESCRIPTOR.message_types_by_name['SiteDataProto'] = _SITEDATAPROTO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SiteDataFeatureProto = _reflection.GeneratedProtocolMessageType('SiteDataFeatureProto', (_message.Message,), {
  'DESCRIPTOR' : _SITEDATAFEATUREPROTO,
  '__module__' : 'site_data_pb2'
  
  })
_sym_db.RegisterMessage(SiteDataFeatureProto)

SiteDataPerformanceMeasurement = _reflection.GeneratedProtocolMessageType('SiteDataPerformanceMeasurement', (_message.Message,), {
  'DESCRIPTOR' : _SITEDATAPERFORMANCEMEASUREMENT,
  '__module__' : 'site_data_pb2'
  
  })
_sym_db.RegisterMessage(SiteDataPerformanceMeasurement)

SiteDataProto = _reflection.GeneratedProtocolMessageType('SiteDataProto', (_message.Message,), {
  'DESCRIPTOR' : _SITEDATAPROTO,
  '__module__' : 'site_data_pb2'
  
  })
_sym_db.RegisterMessage(SiteDataProto)


DESCRIPTOR._options = None

