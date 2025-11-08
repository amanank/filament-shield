<?php

declare(strict_types=1);

namespace BezhanSalleh\FilamentShield\Traits;

use BezhanSalleh\FilamentShield\Support\Utils;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

trait HasShieldRelationManagerAccess {
    /**
     * Override the can() method to check relation manager specific permissions
     * This is called by canCreate(), canEdit(), canDelete(), etc.
     */
    protected function can(string $action, ?\Illuminate\Database\Eloquent\Model $record = null): bool {
        // If relation managers are not enabled, use parent's authorization
        if (! config('filament-shield.relation_managers.enabled')) {
            return parent::can($action, $record);
        }

        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            return false;
        }

        $resourceSlug = $this->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return parent::can($action, $record);
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Generate the permission key
        $permissionName = Utils::generateRelationManagerPermissionKey(
            $action,
            $resourceSlug,
            $relationManagerClass,
        );

        \Illuminate\Support\Facades\Log::info('Shield trait checking permission', [
            'action' => $action,
            'resourceSlug' => $resourceSlug,
            'relationManagerClass' => $relationManagerClass,
            'permissionName' => $permissionName,
            'userPermissions' => $user->getAllPermissions()->pluck('name')->filter(fn($p) => str_contains($p, $resourceSlug))->values()->all(),
        ]);

        // Check if user has the specific relation manager permission
        if ($user->can($permissionName)) {
            \Illuminate\Support\Facades\Log::info('Shield: User has relation manager permission', ['permission' => $permissionName]);
            return true;
        }

        // Fall back to resource permission
        $resourcePermissionName = "{$action}_{$resourceSlug}";
        $hasResourcePerm = $user->can($resourcePermissionName);
        \Illuminate\Support\Facades\Log::info('Shield: Checking resource permission', ['permission' => $resourcePermissionName, 'result' => $hasResourcePerm]);
        return $hasResourcePerm;
    }

    /**
     * Check if the user can view this relation manager.
     * If relation_managers are enabled, checks specific permission,
     * otherwise falls back to resource permission.
     */
    protected function canView(Model $record): bool {
        $result = $this->can('view', $record);
        \Illuminate\Support\Facades\Log::info('Shield canView', ['result' => $result, 'class' => static::class]);
        return $result;
    }

    /**
     * Check if the user can create records in this relation manager.
     */
    protected function canCreate(): bool {
        $result = $this->can('create');
        \Illuminate\Support\Facades\Log::info('Shield canCreate', ['result' => $result, 'class' => static::class]);
        return $result;
    }

    /**
     * Check if the user can update records in this relation manager.
     */
    protected function canEdit(Model $record): bool {
        $result = $this->can('update', $record);
        \Illuminate\Support\Facades\Log::info('Shield canEdit', ['result' => $result, 'class' => static::class]);
        return $result;
    }

    /**
     * Check if the user can delete records in this relation manager.
     */
    protected function canDelete(Model $record): bool {
        $result = $this->can('delete', $record);
        \Illuminate\Support\Facades\Log::info('Shield canDelete', ['result' => $result, 'class' => static::class]);
        return $result;
    }

    /**
     * Extract resource slug from the relation manager's namespace
     * Example: App\Filament\Admin\Resources\MemberResource\RelationManagers\HistoryRelationManager
     * Returns: member
     */
    protected function extractResourceSlugFromNamespace(): ?string {
        $namespace = static::class;

        // Extract the resource class name from namespace
        if (preg_match('/Resources\\\\(\w+Resource)\\\\RelationManagers/', $namespace, $matches)) {
            $resourceClass = $matches[1];

            // Convert MemberResource -> member
            return Str::of($resourceClass)
                ->beforeLast('Resource')
                ->kebab()
                ->toString();
        }

        return null;
    }

    /**
     * Check if the user can view this relation manager for a specific owner record
     * This is called by Filament to determine if the relation manager tab should be visible
     */
    public static function canViewForRecord(Model $ownerRecord, string $pageClass): bool {
        // Get a temporary instance to extract the resource slug
        $tempInstance = new static();
        $resourceSlug = $tempInstance->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            $result = parent::canViewForRecord($ownerRecord, $pageClass);
            \Illuminate\Support\Facades\Log::info('Shield canViewForRecord (no resource slug)', ['result' => $result, 'class' => static::class]);
            return $result;
        }

        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            \Illuminate\Support\Facades\Log::info('Shield canViewForRecord (no user)', ['class' => static::class]);
            return false;
        }

        // Check if relation managers are enabled
        if (! config('filament-shield.relation_managers.enabled')) {
            $result = parent::canViewForRecord($ownerRecord, $pageClass);
            \Illuminate\Support\Facades\Log::info('Shield canViewForRecord (disabled)', ['result' => $result, 'class' => static::class]);
            return $result;
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Generate the permission key for 'view'
        $permissionName = Utils::generateRelationManagerPermissionKey(
            'view',
            $resourceSlug,
            $relationManagerClass,
        );

        \Illuminate\Support\Facades\Log::info('Shield canViewForRecord checking', [
            'resourceSlug' => $resourceSlug,
            'permissionName' => $permissionName,
            'class' => static::class,
        ]);

        // Check if user has the specific relation manager permission
        if ($user->can($permissionName)) {
            \Illuminate\Support\Facades\Log::info('Shield canViewForRecord: User has permission', ['permission' => $permissionName]);
            return true;
        }

        // Fall back to checking resource permission
        $resourcePermissionName = "view_{$resourceSlug}";
        $result = $user->can($resourcePermissionName);
        \Illuminate\Support\Facades\Log::info('Shield canViewForRecord: Fallback check', ['permission' => $resourcePermissionName, 'result' => $result]);
        return $result;
    }

    /**
     * Check if the relation manager should be read-only
     * Returns false if the user has create/update/delete permissions, true otherwise
     */
    public function isReadOnly(): bool {
        // Check if relation managers are enabled
        if (! config('filament-shield.relation_managers.enabled')) {
            return parent::isReadOnly();
        }

        $resourceSlug = $this->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return parent::isReadOnly();
        }

        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            \Illuminate\Support\Facades\Log::info('Shield isReadOnly (no user)', ['class' => static::class]);
            return true;
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Check if user has any write permissions (create, update, or delete)
        $canCreate = Utils::generateRelationManagerPermissionKey('create', $resourceSlug, $relationManagerClass);
        $canUpdate = Utils::generateRelationManagerPermissionKey('update', $resourceSlug, $relationManagerClass);
        $canDelete = Utils::generateRelationManagerPermissionKey('delete', $resourceSlug, $relationManagerClass);

        $hasWritePermission = $user->can($canCreate) || $user->can($canUpdate) || $user->can($canDelete);

        // If no relation-specific permissions, check resource-level permissions
        if (! $hasWritePermission) {
            $hasWritePermission = $user->can("create_{$resourceSlug}") ||
                $user->can("update_{$resourceSlug}") ||
                $user->can("delete_{$resourceSlug}");
        }

        $isReadOnly = ! $hasWritePermission;
        \Illuminate\Support\Facades\Log::info('Shield isReadOnly', [
            'isReadOnly' => $isReadOnly,
            'hasWritePermission' => $hasWritePermission,
            'class' => static::class,
        ]);

        return $isReadOnly;
    }
}
