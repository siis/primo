# Copyright (C) 2015 The Pennsylvania State University and the University of Wisconsin
# Systems and Internet Infrastructure Security Laboratory
#
# Author: Damien Octeau
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from primo.linking.applications cimport Application
from primo.linking.components cimport Component
from primo.linking.intent_filters cimport IntentFilter

cdef void PrepareForQueries(set applications)
cdef int GetExportedComponentCount(int kind, set search_space=?)
cdef set GetAppsMatching(unicode app_name, unicode component_name)
cdef set GetComponentsOfApp(unicode app_name, set search_space)
cdef set GetComponentsWithName(unicode component_name, set search_space)
cdef set GetComponentsWithKind(int kind, set search_space)
cdef set GetFiltersWithUsedPermission(unicode used_permission,
                                      set search_space)
cdef set GetFiltersWithAction(unicode action, set search_space)
cdef set GetFiltersOfApp(unicode app, set search_space)
cdef set GetFiltersWithKind(int kind, set search_space)
cdef set GetFiltersWithAnyAction(set search_space)
cdef set GetFiltersWithCategories(tuple categories, set search_space)
cdef set GetFiltersWithTypes(list mime_types, set search_space)
cdef set GetFiltersWithBaseTypes(list base_types, search_space)
cdef set GetFiltersWithScheme(unicode scheme, set search_space)
cdef set GetFiltersWithHost(unicode host, set search_space)
cdef set GetFiltersWithPort(unicode port, set search_space)
cdef set GetFiltersWithPath(unicode path, set search_space)
cdef set GetExportedFilters(set search_space)
cdef set GetFiltersWithoutType(set search_space)
cdef set GetNoDataFilters(set search_space)
cdef set GetFiltersWithType(set search_space)
cdef long GetTargetCountForValue(object field, object value)
cdef void AddIntentFilterAttributes(IntentFilter intent_filter, dict attributes)
cdef void AddComponent(Component component)
cdef set GetExportedComponents(set search_space)
