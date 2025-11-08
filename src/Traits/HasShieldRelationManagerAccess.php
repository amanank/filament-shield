<?php

declare(strict_types=1);

namespace BezhanSalleh\FilamentShield\Traits;

use BezhanSalleh\FilamentShield\Support\Utils;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

trait HasShieldRelationManagerAccess {
    /**
     * Check if the user can view this relation manager.
     * If relation_managers are enabled, checks specific permission,
     * otherwise falls back to resource permission.
     */
    protected function canView(Model $record): bool {
        return $this->checkRelationManagerPermission('view');
    }

    /**
     * Check if the user can create records in this relation manager.
     */
    protected function canCreate(): bool {
        return $this->checkRelationManagerPermission('create');
    }

    /**
     * Check if the user can update records in this relation manager.
     */
    protected function canEdit(Model $record): bool {
        return $this->checkRelationManagerPermission('update');
    }

    /**
     * Check if the user can delete records in this relation manager.
     */
    protected function canDelete(Model $record): bool {
        return $this->checkRelationManagerPermission('delete');
    }

    /**
     * Check relation manager specific permission or fall back to resource permission
     */
    protected function checkRelationManagerPermission(string $operation): bool {
        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            return false;
        }

        // If relation managers are not enabled, fall back to resource permissions
        if (! config('filament-shield.relation_managers.enabled')) {
            return $this->fallbackToResourcePermission($operation);
        }

        // Get the resource slug from the parent resource
        // The parent resource is available via $this->getOwnerRecord() but we need the resource class
        // We extract it from the namespace: App\Filament\Admin\Resources\MemberResource\RelationManagers\HistoryRelationManager
        $resourceSlug = $this->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return $this->fallbackToResourcePermission($operation);
        }

        // Get the relation manager class name
        $relationManagerClass = static::class;

        // Generate the permission key
        $permissionName = Utils::generateRelationManagerPermissionKey(
            $operation,
            $resourceSlug,
            $relationManagerClass,
        );

        // Check if user has the specific relation manager permission
        if ($user->can($permissionName)) {
            return true;
        }

        // Fall back to resource permission
        return $this->fallbackToResourcePermission($operation);
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
     * Fall back to checking the resource permission
     */
    protected function fallbackToResourcePermission(string $operation): bool {
        $user = auth(Utils::getFilamentAuthGuard())->user();

        if (! $user) {
            return false;
        }

        $resourceSlug = $this->extractResourceSlugFromNamespace();

        if (! $resourceSlug) {
            return false;
        }

        $permissionName = "{$operation}_{$resourceSlug}";

        return $user->can($permissionName);
    }
}
