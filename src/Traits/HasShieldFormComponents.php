<?php

declare(strict_types=1);

namespace BezhanSalleh\FilamentShield\Traits;

use BezhanSalleh\FilamentShield\Facades\FilamentShield;
use BezhanSalleh\FilamentShield\FilamentShieldPlugin;
use BezhanSalleh\FilamentShield\Support\Utils;
use Filament\Forms;
use Filament\Forms\Components\Component;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\HtmlString;

trait HasShieldFormComponents {
    public static function getShieldFormComponents(): Component {
        $tabs = [
            static::getTabFormComponentForResources(),
            static::getTabFormComponentForPage(),
            static::getTabFormComponentForWidget(),
            static::getTabFormComponentForCustomPermissions(),
        ];

        return Forms\Components\Tabs::make('Permissions')
            ->contained()
            ->tabs($tabs)
            ->columnSpan('full');
    }

    public static function getResourceEntitiesSchema(): ?array {
        return collect(FilamentShield::getResources())
            ->sortKeys()
            ->map(function ($entity) {
                $sectionLabel = strval(
                    static::shield()->hasLocalizedPermissionLabels()
                        ? FilamentShield::getLocalizedResourceLabel($entity['fqcn'])
                        : $entity['model']
                );

                $schema = [
                    static::getCheckBoxListComponentForResource($entity),
                ];

                // Add relation manager permissions if enabled
                if (config('filament-shield.relation_managers.enabled')) {
                    $relationManagerPermissions = static::getRelationManagerPermissionsForResource($entity);
                    if (! empty($relationManagerPermissions)) {
                        $schema[] = Forms\Components\Section::make('Relation Managers')
                            ->compact()
                            ->schema([
                                Forms\Components\CheckboxList::make($entity['resource'] . '_relation_managers')
                                    ->label('')
                                    ->options(fn(): array => $relationManagerPermissions)
                                    ->searchable(false)
                                    ->afterStateHydrated(
                                        fn(Component $component, string $operation, ?Model $record) => static::setPermissionStateForRecordPermissions(
                                            component: $component,
                                            operation: $operation,
                                            permissions: $relationManagerPermissions,
                                            record: $record
                                        )
                                    )
                                    ->dehydrated()
                                    ->bulkToggleable()
                                    ->gridDirection('row')
                                    ->columns(static::shield()->getResourceCheckboxListColumns())
                                    ->columnSpan(static::shield()->getResourceCheckboxListColumnSpan()),
                            ])
                            ->collapsed();
                    }
                }

                return Forms\Components\Section::make($sectionLabel)
                    ->description(fn() => new HtmlString('<span style="word-break: break-word;">' . Utils::showModelPath($entity['fqcn']) . '</span>'))
                    ->compact()
                    ->schema($schema)
                    ->columnSpan(static::shield()->getSectionColumnSpan())
                    ->collapsible();
            })
            ->toArray();
    }

    public static function getResourceTabBadgeCount(): ?int {
        $count = collect(FilamentShield::getResources())
            ->map(fn($resource) => count(static::getResourcePermissionOptions($resource)))
            ->sum();

        if (config('filament-shield.relation_managers.enabled')) {
            $count += collect(FilamentShield::getResources())
                ->map(fn($resource) => count(static::getRelationManagerPermissionsForResource($resource)))
                ->sum();
        }

        return $count;
    }

    public static function getResourcePermissionOptions(array $entity): array {
        return collect(Utils::getResourcePermissionPrefixes($entity['fqcn']))
            ->flatMap(function ($permission) use ($entity) {
                $name = $permission . '_' . $entity['resource'];
                $label = static::shield()->hasLocalizedPermissionLabels()
                    ? FilamentShield::getLocalizedResourcePermissionLabel($permission)
                    : $name;

                return [
                    $name => $label,
                ];
            })
            ->toArray();
    }

    public static function getRelationManagerPermissionsForResource(array $entity): array {
        $resourceSlug = $entity['resource'];
        // Use escaped underscores to match the exact pattern {operation}_{resourceSlug}__{relationKey}
        $permissions = Utils::getPermissionModel()::where('name', 'like', '%' . $resourceSlug . '\_\_%')->get();

        // Build labels as "Operation RelationName" e.g. "View Communications"
        $grouped = [];
        foreach ($permissions as $permission) {
            // Extract operation (view, create, update, delete, etc.)
            $operationPart = str($permission->name)
                ->before($resourceSlug)
                ->rtrim('_')
                ->toString();

            // Extract just the relation name part after "__"
            $relationPart = str($permission->name)
                ->after('__')
                ->replace('_', ' ')
                ->headline()
                ->toString();

            // Build label as "Operation Relation"
            $label = str($operationPart)
                ->headline()
                ->append(' ' . $relationPart)
                ->toString();

            // Use the full permission name as the key, but with a cleaner label
            $grouped[$permission->name] = $label;
        }

        return $grouped;
    }

    public static function setPermissionStateForRecordPermissions(Component $component, string $operation, array $permissions, ?Model $record): void {
        if (in_array($operation, ['edit', 'view'])) {

            if (blank($record)) {
                return;
            }
            if ($component->isVisible() && count($permissions) > 0) {
                $component->state(
                    collect($permissions)
                        /** @phpstan-ignore-next-line */
                        ->filter(fn($value, $key) => $record->checkPermissionTo($key))
                        ->keys()
                        ->toArray()
                );
            }
        }
    }

    public static function getPageOptions(): array {
        return collect(FilamentShield::getPages())
            ->flatMap(fn($page) => [
                $page['permission'] => static::shield()->hasLocalizedPermissionLabels()
                    ? FilamentShield::getLocalizedPageLabel($page['class'])
                    : $page['permission'],
            ])
            ->toArray();
    }

    public static function getWidgetOptions(): array {
        return collect(FilamentShield::getWidgets())
            ->flatMap(fn($widget) => [
                $widget['permission'] => static::shield()->hasLocalizedPermissionLabels()
                    ? FilamentShield::getLocalizedWidgetLabel($widget['class'])
                    : $widget['permission'],
            ])
            ->toArray();
    }

    public static function getCustomPermissionOptions(): ?array {
        return FilamentShield::getCustomPermissions()
            ->reject(fn($perm) => str_contains($perm, '__'))  // ⛔ skip relation-manager permissions
            ->mapWithKeys(fn($customPermission) => [
                $customPermission => static::shield()->hasLocalizedPermissionLabels() ? str($customPermission)->headline()->toString() : $customPermission,
            ])
            ->toArray();
    }

    public static function getTabFormComponentForResources(): Component {
        return static::shield()->hasSimpleResourcePermissionView()
            ? static::getTabFormComponentForSimpleResourcePermissionsView()
            : Forms\Components\Tabs\Tab::make('resources')
            ->label(__('filament-shield::filament-shield.resources'))
            ->visible(fn(): bool => (bool) Utils::isResourceEntityEnabled())
            ->badge(static::getResourceTabBadgeCount())
            ->schema([
                Forms\Components\Grid::make()
                    ->schema(static::getResourceEntitiesSchema())
                    ->columns(static::shield()->getGridColumns()),
            ]);
    }

    public static function getCheckBoxListComponentForResource(array $entity): Component {
        $permissionsArray = static::getResourcePermissionOptions($entity);

        return static::getCheckboxListFormComponent(
            name: $entity['resource'],
            options: $permissionsArray,
            columns: static::shield()->getResourceCheckboxListColumns(),
            columnSpan: static::shield()->getResourceCheckboxListColumnSpan(),
            searchable: false
        );
    }

    public static function getTabFormComponentForPage(): Component {
        $options = static::getPageOptions();
        $count = count($options);

        return Forms\Components\Tabs\Tab::make('pages')
            ->label(__('filament-shield::filament-shield.pages'))
            ->visible(fn(): bool => (bool) Utils::isPageEntityEnabled() && $count > 0)
            ->badge($count)
            ->schema([
                static::getCheckboxListFormComponent(
                    name: 'pages_tab',
                    options: $options,
                ),
            ]);
    }

    public static function getTabFormComponentForWidget(): Component {
        $options = static::getWidgetOptions();
        $count = count($options);

        return Forms\Components\Tabs\Tab::make('widgets')
            ->label(__('filament-shield::filament-shield.widgets'))
            ->visible(fn(): bool => (bool) Utils::isWidgetEntityEnabled() && $count > 0)
            ->badge($count)
            ->schema([
                static::getCheckboxListFormComponent(
                    name: 'widgets_tab',
                    options: $options,
                ),
            ]);
    }

    public static function getTabFormComponentForCustomPermissions(): Component {
        $options = static::getCustomPermissionOptions();
        $count = count($options);

        return Forms\Components\Tabs\Tab::make('custom')
            ->label(__('filament-shield::filament-shield.custom'))
            ->visible(fn(): bool => (bool) Utils::isCustomPermissionEntityEnabled() && $count > 0)
            ->badge($count)
            ->schema([
                static::getCheckboxListFormComponent(
                    name: 'custom_permissions',
                    options: $options,
                ),
            ]);
    }

    public static function getTabFormComponentForRelationManagers(): Component {
        $options = static::getRelationManagerPermissionOptions();
        $count = count($options);

        return Forms\Components\Tabs\Tab::make('relations')
            ->label('Relation Managers')
            ->visible(fn(): bool => (bool) count($options) > 0)
            ->badge($count)
            ->schema([
                static::getCheckboxListFormComponent(
                    name: 'relation_managers_tab',
                    options: $options,
                ),
            ]);
    }

    public static function getRelationManagerPermissionOptions(): array {
        $permissions = Utils::getPermissionModel()::where('name', 'like', '%__%')->get();

        return $permissions
            ->mapWithKeys(fn($permission) => [
                $permission->name => static::shield()->hasLocalizedPermissionLabels()
                    ? str($permission->name)->headline()->toString()
                    : $permission->name,
            ])
            ->toArray();
    }

    public static function getTabFormComponentForSimpleResourcePermissionsView(): Component {
        $options = FilamentShield::getAllResourcePermissions();
        $count = count($options);

        return Forms\Components\Tabs\Tab::make('resources')
            ->label(__('filament-shield::filament-shield.resources'))
            ->visible(fn(): bool => (bool) Utils::isResourceEntityEnabled() && $count > 0)
            ->badge($count)
            ->schema([
                static::getCheckboxListFormComponent(
                    name: 'resources_tab',
                    options: $options,
                ),
            ]);
    }

    public static function getCheckboxListFormComponent(string $name, array $options, bool $searchable = true, array | int | string | null $columns = null, array | int | string | null $columnSpan = null): Component {
        return Forms\Components\CheckboxList::make($name)
            ->label('')
            ->options(fn(): array => $options)
            ->searchable($searchable)
            ->afterStateHydrated(
                fn(Component $component, string $operation, ?Model $record) => static::setPermissionStateForRecordPermissions(
                    component: $component,
                    operation: $operation,
                    permissions: $options,
                    record: $record
                )
            )
            ->dehydrated()
            ->bulkToggleable()
            ->gridDirection('row')
            ->columns($columns ?? static::shield()->getCheckboxListColumns())
            ->columnSpan($columnSpan ?? static::shield()->getCheckboxListColumnSpan());
    }

    public static function shield(): FilamentShieldPlugin {
        return FilamentShieldPlugin::get();
    }
}
